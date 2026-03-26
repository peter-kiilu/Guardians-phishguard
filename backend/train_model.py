import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression
from feature_extractor import get_feature_vector

# Synthetic Dataset Generation
# Features: [url_length, num_dots, num_hyphens, at_symbol, has_ip, is_https, suspicious_count, num_subdomains]

def generate_synthetic_data():
    X = []
    y = []

    # Safe URLs examples
    safe_urls = [
        "https://www.google.com",
        "https://github.com/trending",
        "https://www.amazon.com/gp/cart",
        "https://stackoverflow.com/questions",
        "https://www.nytimes.com",
        "https://medium.com",
        "https://en.wikipedia.org/wiki/Main_Page",
        "https://www.apple.com/shop",
        "https://www.microsoft.com/en-us",
        "https://www.linkedin.com/feed/"
    ]

    # Phishing URLs examples (Lexical patterns)
    phishing_urls = [
        "http://secure-login-verify-account.tk",
        "http://192.168.1.1/login.html",
        "http://update-bank-info.ru/secure",
        "http://verify@account-update.xyz/login",
        "http://paypal-secure-check.tk/update",
        "http://bank-of-america-verify.net-auth.top",
        "http://login.microsoft-security-update.xyz",
        "http://very-long-suspicious-url-with-many-dots.login-check.ru/verify",
        "http://account-verification-step1.tk",
        "http://secure-banking-portal.tk/login"
    ]

    for url in safe_urls:
        X.append(get_feature_vector(url))
        y.append(0) # 0 for Safe

    for url in phishing_urls:
        X.append(get_feature_vector(url))
        y.append(1) # 1 for Phishing

    return np.array(X), np.array(y)

def train_and_save():
    print("Generating synthetic data...")
    X, y = generate_synthetic_data()

    print("Training Logistic Regression model...")
    model = LogisticRegression()
    model.fit(X, y)

    # Simple validation on the training data itself
    score = model.score(X, y)
    print(f"Model Training Accuracy: {score * 100:.2f}%")

    print("Saving model to model.pkl...")
    joblib.dump(model, 'model.pkl')
    print("Done.")

if __name__ == "__main__":
    train_and_save()
