# API Reference

The PhishGuard backend provides two main endpoints for the Chrome extension to interact with.

## Health Check
`GET /`

Returns a simple status message to confirm the API is running.

**Response**
```json
{
  "status": "PhishGuard API is running"
}
```

---

## URL Phishing Detection
`POST /predict`

Analyzes a URL using the trained Logistic Regression model and heuristic rules.

**Request Body**
```json
{
  "url": "http://secure-banking-login.com/verify"
}
```

**Response**
```json
{
  "prediction": "phishing",
  "confidence": 87.5,
  "ml_probability": 0.723,
  "heuristic_score": 15
}
```
- `prediction`: Either "safe" or "phishing".
- `confidence`: The overall confidence percentage (derived from ML and heuristics).
- `ml_probability`: The raw probability score from the Logistic Regression model.
- `heuristic_score`: Added rule-based scoring (e.g., matching a suspicious top-level domain).

---

## Email Phishing Detection
`POST /analyze-email`

Analyzes email content (subject, sender, snippet) to detect phishing/spam patterns.

**Request Body**
```json
{
  "subject": "Verify your account immediately",
  "sender": "security@paypal-verify.com",
  "snippet": "Dear customer, click here to confirm your identity..."
}
```

**Response**
```json
{
  "prediction": "phishing",
  "confidence": 92.3,
  "ml_probability": 0.923,
  "details": "ML classified as phishing with 92.3% confidence"
}
```
- `details`: Provides a human-readable explanation of the prediction result.
