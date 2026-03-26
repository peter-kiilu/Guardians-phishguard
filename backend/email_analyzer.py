import joblib
import os
import logging

logger = logging.getLogger(__name__)

# Model paths
EMAIL_MODEL_PATH = os.path.join(os.path.dirname(__file__), "email_model.pkl")
EMAIL_VECTORIZER_PATH = os.path.join(os.path.dirname(__file__), "email_vectorizer.pkl")

# Lazy-loaded globals
_email_model = None
_email_vectorizer = None


def _load_email_model():
    """Lazy-load the email model and vectorizer."""
    global _email_model, _email_vectorizer

    if _email_model is not None:
        return True

    if not os.path.exists(EMAIL_MODEL_PATH) or not os.path.exists(EMAIL_VECTORIZER_PATH):
        logger.warning("Email model files not found. Run train_model.py first.")
        return False

    try:
        _email_model = joblib.load(EMAIL_MODEL_PATH)
        _email_vectorizer = joblib.load(EMAIL_VECTORIZER_PATH)
        logger.info("Email model and vectorizer loaded successfully.")
        return True
    except Exception as e:
        logger.error(f"Error loading email model: {e}")
        return False


def analyze_email(subject: str, sender: str, snippet: str) -> dict:
    """
    Analyze an email using the trained ML model.

    Args:
        subject: Email subject line
        sender: Sender email address
        snippet: Email body preview/snippet

    Returns:
        dict with prediction, confidence, and details
    """
    if not _load_email_model():
        return {
            "prediction": "unknown",
            "confidence": 0.0,
            "ml_probability": 0.0,
            "details": "Email model not available"
        }

    # Combine text fields for analysis (same approach as training)
    combined_text = f"{subject} {snippet}"

    if not combined_text.strip():
        return {
            "prediction": "unknown",
            "confidence": 0.0,
            "ml_probability": 0.0,
            "details": "No text to analyze"
        }

    try:
        # Vectorize the email text
        X = _email_vectorizer.transform([combined_text])

        # Predict
        probs = _email_model.predict_proba(X)[0]
        phishing_prob = float(probs[1])

        # Determine prediction
        prediction = "phishing" if phishing_prob > 0.5 else "safe"
        confidence = round(phishing_prob * 100, 2) if prediction == "phishing" else round((1 - phishing_prob) * 100, 2)

        return {
            "prediction": prediction,
            "confidence": confidence,
            "ml_probability": round(phishing_prob, 4),
            "details": f"ML classified as {prediction} with {confidence}% confidence"
        }
    except Exception as e:
        logger.error(f"Email analysis error: {e}")
        return {
            "prediction": "unknown",
            "confidence": 0.0,
            "ml_probability": 0.0,
            "details": f"Analysis error: {str(e)}"
        }
