import joblib
import os
import logging
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from feature_extractor import extract_features, get_feature_vector
from urllib.parse import urlparse

# Configure Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="PhishGuard API")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ──────────────────────────────────────────────
#  LOAD MODEL
# ──────────────────────────────────────────────
MODEL_PATH = "model.pkl"
model = None
model_meta = {}

if os.path.exists(MODEL_PATH):
    try:
        artifact = joblib.load(MODEL_PATH)

        # Support both old format (bare model) and new format (dict with metadata)
        if isinstance(artifact, dict):
            model = artifact["model"]
            model_meta = artifact
            logger.info(
                f"ML Model loaded: {artifact.get('model_name', 'Unknown')} "
                f"| Features: {artifact.get('n_features', '?')} "
                f"| Test acc: {artifact.get('test_accuracy', '?'):.4f}"
            )
        else:
            model = artifact
            logger.info("ML Model loaded (legacy format).")
    except Exception as e:
        logger.error(f"Error loading model: {e}")
else:
    logger.warning("Model file not found. Run train_model.py first.")


# ──────────────────────────────────────────────
#  REQUEST / RESPONSE MODELS
# ──────────────────────────────────────────────
class PredictionRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, v):
        if len(v) > 2048:
            raise ValueError("URL exceeds maximum length of 2048 characters")
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v


class PredictionResponse(BaseModel):
    prediction: str
    confidence: float
    ml_probability: float
    heuristic_score: int


# ──────────────────────────────────────────────
#  HEURISTIC ENGINE
# ──────────────────────────────────────────────
def apply_heuristics(url, features):
    """
    Apply rule-based scoring to complement the ML model.
    Returns a score from 0 to ~50.
    """
    score = 0
    parsed = urlparse(url)
    hostname = parsed.hostname or ''

    # +15 if IP address as hostname
    if features['ip']:
        score += 15

    # +10 if suspicious TLD
    if features['suspecious_tld']:
        score += 10

    # +10 if more than 4 dots
    if features['nb_dots'] > 4:
        score += 10

    # +10 if URL length > 75
    if features['length_url'] > 75:
        score += 10

    # +5 if not HTTPS
    if not features['https_token']:
        score += 5

    # +10 if @ symbol present (redirect trick)
    if features['nb_at'] > 0:
        score += 10

    # +8 if excessive hyphens in hostname
    if features['nb_hyphens'] > 3:
        score += 8

    # +5 if punycode domain
    if features['punycode']:
        score += 5

    # +8 if URL shortening service
    if features['shortening_service']:
        score += 8

    # +5 per phishing keyword (capped at 15)
    if features['phish_hints'] > 0:
        score += min(features['phish_hints'] * 5, 15)

    return score


# ──────────────────────────────────────────────
#  ENDPOINTS
# ──────────────────────────────────────────────
@app.get("/")
def read_root():
    return {"status": "PhishGuard API is running"}


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "model_loaded": model is not None,
        "model_name": model_meta.get("model_name", "Unknown"),
        "n_features": model_meta.get("n_features", "?"),
        "test_accuracy": model_meta.get("test_accuracy", "?"),
    }


@app.post("/predict", response_model=PredictionResponse)
async def predict(request: PredictionRequest):
    if not model:
        raise HTTPException(status_code=500, detail="Model not loaded on server.")

    url = request.url
    try:
        # 1. Feature Extraction
        features = extract_features(url)
        vector = get_feature_vector(url)

        # 2. ML Prediction
        # model.predict_proba returns [prob_safe, prob_phishing]
        probs = model.predict_proba([vector])[0]
        ml_prob = float(probs[1])

        # 3. Heuristic Engine
        h_score = apply_heuristics(url, features)

        # 4. Final Score Calculation
        # Base confidence is ML probability * 100, then add heuristic boost
        final_confidence = (ml_prob * 100) + h_score
        final_confidence = min(100.0, final_confidence)

        prediction = "phishing" if final_confidence > 60 else "safe"

        logger.info(
            f"URL: {url} | Prediction: {prediction} | "
            f"Confidence: {final_confidence:.2f}% | ML: {ml_prob:.4f} | H: {h_score}"
        )

        return {
            "prediction": prediction,
            "confidence": round(final_confidence, 2),
            "ml_probability": round(ml_prob, 4),
            "heuristic_score": h_score
        }
    except Exception as e:
        logger.error(f"Prediction error for {url}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Prediction failed. Please try again.")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
