import joblib
import os
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from feature_extractor import get_feature_vector

# Paths 
DATASETS_DIR = os.path.join(os.path.dirname(__file__), "datasets")
URLS_CSV = os.path.join(DATASETS_DIR, "phishing_urls.csv")
EMAILS_CSV = os.path.join(DATASETS_DIR, "emails.csv")

URL_MODEL_PATH = "model.pkl"
EMAIL_MODEL_PATH = "email_model.pkl"
EMAIL_VECTORIZER_PATH = "email_vectorizer.pkl"



#  URL Model — trained from phishing_urls.csv

def load_urls_from_csv(filepath):
    """
    Load URLs from phishing_urls.csv.
    Format: first line is header 'label,url', remaining lines are just URLs.
    Safe URLs use https://, phishing URLs use http://.
    """
    safe_urls = []
    phishing_urls = []

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    for line in lines[1:]:  # Skip header
        url = line.strip()
        if not url:
            continue
        # Phishing URLs in this dataset start with http:// (not https://)
        if url.startswith("http://"):
            phishing_urls.append(url)
        elif url.startswith("https://"):
            safe_urls.append(url)

    return safe_urls, phishing_urls


def train_url_model():
    """Train the URL phishing detection model from phishing_urls.csv."""
    print(f"Loading URLs from {URLS_CSV}...")
    safe_urls, phishing_urls = load_urls_from_csv(URLS_CSV)
    print(f"  Found {len(safe_urls)} safe URLs, {len(phishing_urls)} phishing URLs")

    X = []
    y = []

    for url in safe_urls:
        X.append(get_feature_vector(url))
        y.append(0)  # 0 = Safe

    for url in phishing_urls:
        X.append(get_feature_vector(url))
        y.append(1)  # 1 = Phishing

    X = np.array(X)
    y = np.array(y)

    print("Training URL Logistic Regression model...")
    model = LogisticRegression(max_iter=1000)
    model.fit(X, y)

    score = model.score(X, y)
    print(f"  URL Model Training Accuracy: {score * 100:.2f}%")

    print(f"Saving URL model to {URL_MODEL_PATH}...")
    joblib.dump(model, URL_MODEL_PATH)
    return model


#  Email Model — trained from emails.csv
def load_emails_from_csv(filepath):
    """
    Load emails from emails.csv.
    Format: repeating 3-line groups:
      Line 1: email text
      Line 2: label ("Safe Email" or "Phishing Email")
      Line 3: index number
    """
    emails = []
    labels = []

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    # Strip all lines
    lines = [line.strip() for line in lines]
    # Remove empty leading lines
    while lines and not lines[0]:
        lines.pop(0)

    i = 0
    while i < len(lines):
        # Read email text
        text = lines[i] if i < len(lines) else ""
        i += 1

        # Read label
        label_line = lines[i] if i < len(lines) else ""
        i += 1

        # Read index (skip it)
        i += 1

        # Parse label
        if "Phishing" in label_line:
            label = 1  # Phishing
        elif "Safe" in label_line:
            label = 0  # Safe
        else:
            continue  # Skip malformed entries

        # Skip empty/trivial emails
        if text.lower() in ("empty", ""):
            continue

        emails.append(text)
        labels.append(label)

    return emails, labels


def train_email_model():
    """Train a TF-IDF + Logistic Regression model for email classification."""
    print(f"Loading emails from {EMAILS_CSV}...")
    emails, labels = load_emails_from_csv(EMAILS_CSV)
    print(f"  Found {len(emails)} emails ({labels.count(0)} safe, {labels.count(1)} phishing)")

    if len(emails) < 10:
        print("  Not enough email data to train. Skipping email model.")
        return None, None

    # TF-IDF vectorization
    print("Vectorizing email text with TF-IDF...")
    vectorizer = TfidfVectorizer(
        max_features=5000,
        stop_words="english",
        ngram_range=(1, 2),
        min_df=2,
        max_df=0.95,
    )

    X = vectorizer.fit_transform(emails)
    y = np.array(labels)

    # Train-test split for validation
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("Training Email Logistic Regression model...")
    model = LogisticRegression(max_iter=1000)
    model.fit(X_train, y_train)

    train_score = model.score(X_train, y_train)
    test_score = model.score(X_test, y_test)
    print(f"  Email Model Training Accuracy: {train_score * 100:.2f}%")
    print(f"  Email Model Test Accuracy:     {test_score * 100:.2f}%")

    print(f"Saving email model to {EMAIL_MODEL_PATH}...")
    joblib.dump(model, EMAIL_MODEL_PATH)

    print(f"Saving TF-IDF vectorizer to {EMAIL_VECTORIZER_PATH}...")
    joblib.dump(vectorizer, EMAIL_VECTORIZER_PATH)

    return model, vectorizer


#  Extract phishing domains for the extension
def extract_phishing_domains():
    """Extract unique domains from phishing URLs for use in the extension."""
    from urllib.parse import urlparse

    _, phishing_urls = load_urls_from_csv(URLS_CSV)
    domains = set()

    for url in phishing_urls:
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            if hostname:
                domains.add(hostname.lower())
        except Exception:
            continue

    return sorted(domains)


def generate_phishing_domains_js():
    """
    Auto-generate the KNOWN_PHISHING_DOMAINS set in phishing_domains.js
    from the phishing_urls.csv dataset.
    """
    domains = extract_phishing_domains()
    ext_dir = os.path.join(os.path.dirname(__file__), "..", "extension")
    js_path = os.path.join(ext_dir, "phishing_domains.js")

    print(f"Extracted {len(domains)} phishing domains from dataset.")
    print(f"Updating {js_path}...")

    # Read the existing file
    with open(js_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Build new domain set entries
    domain_entries = ",\n".join(f'  "{d}"' for d in domains)

    # Replace the KNOWN_PHISHING_DOMAINS set contents
    import re
    pattern = r'(const KNOWN_PHISHING_DOMAINS = new Set\(\[)\n.*?(\]\);)'
    replacement = f'\\1\n{domain_entries},\n\\2'
    new_content = re.sub(pattern, replacement, content, flags=re.DOTALL)

    with open(js_path, "w", encoding="utf-8") as f:
        f.write(new_content)

    print(f"  Updated KNOWN_PHISHING_DOMAINS with {len(domains)} domains from dataset.")


#  Main Entry Point

def train_and_save():
    print("=" * 60)
    print("PhishGuard — Model Training Pipeline")
    print("=" * 60)

    # 1. Train URL model
    print("\n[1/3] Training URL Phishing Detection Model")
    print("-" * 40)
    train_url_model()

    # 2. Train Email model
    print("\n[2/3] Training Email Phishing Detection Model")
    print("-" * 40)
    train_email_model()

    # 3. Update extension phishing domains
    print("\n[3/3] Updating Extension Phishing Domains from Dataset")
    print("-" * 40)
    try:
        generate_phishing_domains_js()
    except Exception as e:
        print(f"  Warning: Could not update phishing_domains.js: {e}")

    print("\n" + "=" * 60)
    print("Training complete!")
    print("=" * 60)


if __name__ == "__main__":
    train_and_save()
