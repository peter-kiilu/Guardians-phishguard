# Machine Learning Pipeline

PhishGuard employs two tailored machine learning pipelines: one for URLs and one for Email content.

## URL Classifier

The URL classifier is a **Logistic Regression** model trained on 208 real URLs (106 safe + 101 phishing) residing in `datasets/phishing_urls.csv`.

### Lexical Features

Instead of feeding raw text into the model, PhishGuard extracts 8 distinct *lexical features* from every URL (defined in `feature_extractor.py`):

| # | Feature | Example | Rationale |
|---|---------|---------|-----------|
| 1 | **URL Length** | `len("http://long-url...")` = 78 | Phishing URLs are frequently longer to obscure the path. |
| 2 | **Dot Count** | `"login.bank.com"` → 2 dots | Numerous subdomains suggest malicious structuring. |
| 3 | **Hyphen Count** | `"secure-login"` → 1 hyphen | Attackers use hyphens to mimic legitimate domains. |
| 4 | **@ Symbol** | `"verify@account.xyz"` → 1 | Used to hide the real destination domain. |
| 5 | **IP Address** | `"192.168.1.1/login"` → True | Legitimate websites rarely use raw IP addresses. |
| 6 | **HTTPS** | `"http://..."` → False | Phishing sites often lack an SSL certificate. |
| 7 | **Suspicious Words** | "login", "verify", "update" | Standard keywords in phishing campaigns. |
| 8 | **Subdomain Count** | `"login.secure.bank.com"` → 3 | Subdomain stuffing is common in phishing. |

## Email Classifier

The email classifier processes raw text. It combines the sender, subject, and email snippet into a single document.

1. **TF-IDF Vectorization**: Transforms the email text into numerical feature vectors that represent the importance of specific words.
2. **Logistic Regression**: Trained on approximately 488 emails (`datasets/emails.csv`).

## Training the Models

You can re-train the models at any time by executing:

```bash
python train_model.py
```

### Pipeline Execution Steps:
1. **URL Model Training**: Loads `phishing_urls.csv`, extracts features, trains Logistic Regression, evaluates accuracy, and saves as `model.pkl`.
2. **Email Model Training**: Loads `emails.csv`, fits the TF-IDF vectorizer, trains Logistic Regression, evaluates test accuracy, and saves as `email_vectorizer.pkl` and `email_model.pkl`.
3. **Extension Generation**: Automatically extracts the 101 known phishing domains from the dataset and overwrites `extension/phishing_domains.js` to ensure the Chrome extension remains updated.
