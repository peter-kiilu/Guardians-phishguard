"""
PhishGuard — Model Info
========================
Displays the trained model's metadata, confidence levels,
and runs sample predictions in the terminal.

Usage:
    python model_info.py
    python model_info.py https://example.com   # Test a specific URL
"""

import sys
import joblib
import os
import numpy as np
from feature_extractor import extract_features, get_feature_vector


MODEL_PATH = "model.pkl"


def load_model():
    if not os.path.exists(MODEL_PATH):
        print("ERROR: model.pkl not found. Run train_model.py first.")
        sys.exit(1)

    artifact = joblib.load(MODEL_PATH)

    if isinstance(artifact, dict):
        return artifact["model"], artifact
    else:
        return artifact, {}


def print_header(title):
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}")


def display_model_info(model, meta):
    print_header("MODEL OVERVIEW")
    print(f"  Model type:      {meta.get('model_name', type(model).__name__)}")
    print(f"  Features used:   {meta.get('n_features', '?')}")
    print(f"  Training samples:{meta.get('train_samples', '?')}")
    print(f"  Test accuracy:   {meta.get('test_accuracy', '?'):.4f}")

    # Show feature names
    feature_names = meta.get("feature_names")
    if feature_names:
        print_header("FEATURES")
        for i, name in enumerate(feature_names, 1):
            print(f"  {i:2d}. {name}")


def predict_url(model, url):
    """Run a prediction on a single URL and display detailed results."""
    features = extract_features(url)
    vector = get_feature_vector(url)

    probs = model.predict_proba([vector])[0]
    prob_safe = float(probs[0])
    prob_phish = float(probs[1])
    prediction = "PHISHING" if prob_phish > 0.5 else "SAFE"

    # Confidence = how sure the model is about its chosen class
    confidence = max(prob_safe, prob_phish) * 100

    tag = "!!" if prediction == "PHISHING" else "OK"

    print(f"\n  [{tag}] {url}")
    print(f"      Verdict:        {prediction}")
    print(f"      Confidence:     {confidence:.1f}%")
    print(f"      P(safe):        {prob_safe:.4f}")
    print(f"      P(phishing):    {prob_phish:.4f}")

    # Show top contributing features
    notable = {k: v for k, v in features.items() if v != 0}
    if notable:
        print(f"      Key signals:    ", end="")
        items = list(notable.items())[:6]
        print(", ".join(f"{k}={v}" for k, v in items))

    return prediction, confidence


def main():
    model, meta = load_model()

    display_model_info(model, meta)

    # If user passed a URL as argument, test just that
    if len(sys.argv) > 1:
        url = sys.argv[1]
        print_header("CUSTOM URL TEST")
        predict_url(model, url)
        print()
        return

    # Otherwise run the standard demo suite
    print_header("CONFIDENCE LEVELS — SAMPLE PREDICTIONS")

    test_urls = [
        # Safe URLs
        "https://www.google.com",
        "https://github.com/features",
        "https://www.amazon.com/gp/cart",
        "https://stackoverflow.com/questions",
        "https://www.wikipedia.org",
        # Phishing URLs
        "http://secure-login-verify-account.tk",
        "http://192.168.1.1/login.html",
        "http://update-bank-info.ru/secure",
        "http://verify@account-update.xyz/login",
        "http://paypal-secure-check.tk/update",
    ]

    safe_confidences = []
    phish_confidences = []

    for url in test_urls:
        pred, conf = predict_url(model, url)
        if pred == "SAFE":
            safe_confidences.append(conf)
        else:
            phish_confidences.append(conf)

    # Summary stats
    print_header("CONFIDENCE SUMMARY")

    if safe_confidences:
        print(f"  Safe detections ({len(safe_confidences)}):")
        print(f"      Average confidence:  {np.mean(safe_confidences):.1f}%")
        print(f"      Min confidence:      {np.min(safe_confidences):.1f}%")
        print(f"      Max confidence:      {np.max(safe_confidences):.1f}%")

    if phish_confidences:
        print(f"  Phishing detections ({len(phish_confidences)}):")
        print(f"      Average confidence:  {np.mean(phish_confidences):.1f}%")
        print(f"      Min confidence:      {np.min(phish_confidences):.1f}%")
        print(f"      Max confidence:      {np.max(phish_confidences):.1f}%")

    print(f"\n{'─' * 60}")
    print(f"  Model: {meta.get('model_name', 'Unknown')} | "
          f"Test Accuracy: {meta.get('test_accuracy', 0):.2%} | "
          f"Features: {meta.get('n_features', '?')}")
    print(f"{'─' * 60}\n")


if __name__ == "__main__":
    main()
