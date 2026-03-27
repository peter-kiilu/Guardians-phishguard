import joblib
import os
import logging
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from feature_extractor import extract_features, get_feature_vector
from email_analyzer import analyze_email
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
    content: str
    content_type: str = 'url'  # 'url' or 'email'


class PredictionResponse(BaseModel):
    prediction: str
    confidence: float
    ml_probability: float = 0.0
    heuristic_score: int = 0
    explanation: str = ''
    recommendations: list = []

class EmailAnalysisRequest(BaseModel):
    subject: str = ""
    sender: str = ""
    snippet: str = ""

class EmailAnalysisResponse(BaseModel):
    prediction: str
    confidence: float
    ml_probability: float
    details: str

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
    if request.content_type == 'url':
        if not model:
            raise HTTPException(status_code=500, detail="Model not loaded on server.")
        url = request.content
        try:
            features = extract_features(url)
            vector = get_feature_vector(url)
            probs = model.predict_proba([vector])[0]
            ml_prob = float(probs[1])
            h_score = apply_heuristics(url, features)
            final_confidence = (ml_prob * 100) + h_score
            final_confidence = min(100.0, final_confidence)
            prediction = "phishing" if final_confidence > 60 else "safe"
            explanation = "This link appears {}. {}".format(
                "malicious" if prediction == "phishing" else "safe",
                "Multiple suspicious features detected." if prediction == "phishing" else "No major threats found."
            )
            recommendations = [
                "Do not click suspicious links.",
                "Check the sender's address.",
                "If unsure, verify with the organization directly."
            ] if prediction == "phishing" else [
                "Stay vigilant when clicking links online."
            ]
            logger.info(f"URL: {url} | Prediction: {prediction} | Confidence: {final_confidence:.2f}%")
            return {
                "prediction": prediction,
                "confidence": round(final_confidence, 2),
                "ml_probability": round(ml_prob, 4),
                "heuristic_score": h_score,
                "explanation": explanation,
                "recommendations": recommendations,
                "keywords": list(features.keys())[:5] # Adding some features as keywords for UI consistency
            }
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    elif request.content_type == 'email':
        # Simple heuristic for email: look for suspicious words, links, and urgency
        content = request.content
        suspicious_words = ['login', 'verify', 'secure', 'bank', 'update', 'account', 'urgent', 'immediately', 'password', 'confirm', 'click', 'reset', 'alert', 'locked', 'suspend', 'invoice', 'payment', 'refund']
        found_words = [w for w in suspicious_words if w in content.lower()]
        num_links = content.count('http://') + content.count('https://')
        has_urgency = any(w in content.lower() for w in ['urgent', 'immediately', 'asap', 'now'])
        score = len(found_words) * 10 + num_links * 15 + (20 if has_urgency else 0)
        prediction = 'phishing' if score > 40 else 'suspicious' if score > 20 else 'safe'
        explanation = f"This email contains {len(found_words)} suspicious keywords and {num_links} links."
        if has_urgency:
            explanation += " It also contains urgent language."
        recommendations = []
        if prediction == 'phishing':
            recommendations = [
                "Do NOT click any links in this email.",
                "Do NOT provide any personal or financial information.",
                "Report this message to your IT/security team.",
                "Delete this message immediately."
            ]
        elif prediction == 'suspicious':
            recommendations = [
                "Verify the sender through official channels before responding.",
                "Be cautious about clicking links or providing information.",
                "Contact the supposed sender through known contact methods."
            ]
        else:
            recommendations = [
                "Always verify sender identity for financial requests.",
                "Keep your security software updated."
            ]
        return {
            "prediction": prediction,
            "confidence": min(100, score),
            "ml_probability": 0.0,
            "heuristic_score": score,
            "explanation": explanation,
            "recommendations": recommendations,
            "keywords": found_words
        }
    else:
        raise HTTPException(status_code=400, detail="Unsupported content_type. Use 'url' or 'email'.")

@app.post("/analyze-email", response_model=EmailAnalysisResponse)
async def analyze_email_endpoint(request: EmailAnalysisRequest):
    """Analyze email content for phishing using the trained email ML model."""
    try:
        result = analyze_email(
            subject=request.subject,
            sender=request.sender,
            snippet=request.snippet
        )

        logger.info(
            f"Email Analysis | Subject: {request.subject[:50]}... | "
            f"Prediction: {result['prediction']} | Confidence: {result['confidence']}%"
        )

        return result
    except Exception as e:
        logger.error(f"Email analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
