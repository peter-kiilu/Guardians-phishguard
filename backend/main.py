import joblib
import os
import logging
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
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

# Load Model
MODEL_PATH = "model.pkl"
model = None

if os.path.exists(MODEL_PATH):
    try:
        model = joblib.load(MODEL_PATH)
        logger.info("ML Model loaded successfully.")
    except Exception as e:
        logger.error(f"Error loading model: {e}")
else:
    logger.warning("Model file not found. Run train_model.py first.")

class PredictionRequest(BaseModel):
    url: str

class PredictionResponse(BaseModel):
    prediction: str
    confidence: float
    ml_probability: float
    heuristic_score: int

def apply_heuristics(url, features):
    """
    Apply rule-based scoring to complement the ML model.
    """
    score = 0
    parsed = urlparse(url)
    hostname = parsed.hostname or ''
    
    # +15 if IP address
    if features['has_ip']:
        score += 15
        
    # +10 if suspicious TLD
    suspicious_tlds = ['.ru', '.tk', '.xyz', '.top', '.pw', '.ga', '.ml', '.cf']
    if any(hostname.endswith(tld) for tld in suspicious_tlds):
        score += 10
        
    # +10 if more than 4 dots
    if features['num_dots'] > 4:
        score += 10
        
    # +10 if URL length > 75
    if features['url_length'] > 75:
        score += 10
        
    # +5 if not HTTPS
    if not features['is_https']:
        score += 5
        
    return score

@app.get("/")
def read_root():
    return {"status": "PhishGuard API is running"}

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
        # Final confidence is weighted ML + Heuristics
        # Base confidence is ML prob * 100, then we add heuristics
        final_confidence = (ml_prob * 100) + h_score
        final_confidence = min(100.0, final_confidence)
        
        prediction = "phishing" if final_confidence > 60 else "safe"
        
        logger.info(f"URL: {url} | Prediction: {prediction} | Confidence: {final_confidence:.2f}%")
        
        return {
            "prediction": prediction,
            "confidence": round(final_confidence, 2),
            "ml_probability": round(ml_prob, 4),
            "heuristic_score": h_score
        }
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
