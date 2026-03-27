# PhishGuard 🛡️

**Real-time phishing detection powered by Machine Learning, heuristic analysis, and Gmail email scanning.**

PhishGuard is a comprehensive cybersecurity system that protects users from phishing attacks across two surfaces: **malicious URLs** (detected in real-time as you browse) and **phishing emails** (scanned directly inside Gmail). It combines a trained ML backend with a Chrome extension that acts as your always-on security shield.

---

## 🎯 How It Works

PhishGuard uses a **multi-layered detection approach**:

```
┌─────────────────────────────────────────────────────────────────┐
│                        DETECTION LAYERS                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Layer 1: ML URL Classifier (Logistic Regression)               │
│  ├── Trained on 208 real URLs (106 safe + 101 phishing)         │
│  ├── Extracts 8 lexical features from every URL                 │
│  └── Predicts phishing probability in milliseconds              │
│                                                                 │
│  Layer 2: Heuristic Engine (Rule-Based Scoring)                 │
│  ├── Suspicious TLDs (.tk, .xyz, .ru, .ga, .ml, .cf)           │
│  ├── IP-based hostnames, excessive dots, long URLs              │
│  └── Missing HTTPS                                              │
│                                                                 │
│  Layer 3: ML Email Classifier (TF-IDF + Logistic Regression)   │
│  ├── Trained on ~488 real emails (safe + phishing)              │
│  ├── Analyzes subject lines and email snippets                  │
│  └── Detects spam/phishing language patterns                    │
│                                                                 │
│  Layer 4: Gmail DOM Scanner (Content Script)                    │
│  ├── 101 known phishing domains (extracted from dataset)        │
│  ├── 65+ urgency phrases ("verify your account", etc.)          │
│  ├── URL shortener detection (bit.ly, tinyurl, etc.)            │
│  └── Mismatched link detection (display vs. actual URL)         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### URL Protection Flow

1. You navigate to a website → the **Chrome extension** captures the URL
2. The URL is sent to the **FastAPI backend** for analysis
3. The backend extracts **8 lexical features** and runs the **ML model**
4. A **heuristic engine** adds rule-based scoring on top
5. If the combined score exceeds 60% → the page is **blocked** and a warning is shown
6. You can choose to **go back to safety** or **proceed anyway**

### Gmail Email Protection Flow

1. You open **Gmail** → the content script activates automatically
2. A **MutationObserver** watches for inbox changes (Gmail is a Single Page App)
3. For each email row, the scanner extracts **sender, subject, snippet, and links**
4. **Local analysis** checks against known phishing domains, urgency phrases, URL shorteners, and mismatched links
5. **Backend ML analysis** classifies the email text as safe or phishing using the trained TF-IDF model
6. Flagged emails get a **red border** and a **"⚠ Phishing Risk" badge** with a hover tooltip explaining why

---

## 🚀 Key Features

| Feature | Description |
|---------|-------------|
| **Real-time URL Blocking** | Intercepts phishing URLs before the page loads |
| **Gmail Email Scanning** | Scans inbox emails directly from the DOM for phishing indicators |
| **ML-Powered Detection** | Two trained classifiers — one for URLs, one for email content |
| **Dataset-Driven** | Models trained on real phishing URL and email datasets, not hardcoded rules |
| **Known Domain Database** | 101 phishing domains auto-extracted from dataset + 20 URL shortener services |
| **Urgency Phrase Detection** | 65+ phrases like "verify your account", "your account will be closed" |
| **Mismatched Link Detection** | Flags links where displayed text differs from actual destination |
| **Detailed Verdicts** | Shows risk scores, ML probabilities, heuristic contributions, and specific reasons |
| **Privacy-Focused** | All processing is local — no data leaves your machine |
| **Cyberpunk Web Dashboard** | Terminal-style manual URL scanner with Matrix-rain visual effects |

---

## 🛠️ Setup Instructions

### Prerequisites

- Python 3.8+
- Google Chrome
- Git

### 1. Clone & Install

```bash
git clone https://github.com/peter-kiilu/Guardians-phishguard.git
cd Guardians-phishguard

# Set up the backend
cd backend
python -m venv venv

# Activate virtual environment
# Windows:
.\venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Train the ML Models

```bash
cd backend
python train_model.py
```

This will:
- Load **208 URLs** from `datasets/phishing_urls.csv` → train the **URL classifier** (`model.pkl`)
- Load **~488 emails** from `datasets/emails.csv` → train the **email classifier** (`email_model.pkl` + `email_vectorizer.pkl`)
- Auto-update `extension/phishing_domains.js` with **101 phishing domains** extracted from the dataset

Expected output:
```
============================================================
PhishGuard — Model Training Pipeline
============================================================

[1/3] Training URL Phishing Detection Model
  Found 106 safe URLs, 101 phishing URLs
  URL Model Training Accuracy: 99.52%

[2/3] Training Email Phishing Detection Model
  Found ~488 emails (250 safe, 238 phishing)
  Email Model Training Accuracy: ~98%
  Email Model Test Accuracy:     ~95%

[3/3] Updating Extension Phishing Domains from Dataset
  Updated KNOWN_PHISHING_DOMAINS with 101 domains from dataset.

Training complete!
```

### 3. Start the Backend

```bash
cd backend
python main.py
```

The API will run at `http://localhost:8000`. Verify by visiting `http://localhost:8000/` — you should see:
```json
{"status": "PhishGuard API is running"}
```

### 4. Start the Web Dashboard (Optional)

```bash
cd frontend
python -m http.server 5500
```

Access the scanner at `http://localhost:5500`.

### 5. Load the Chrome Extension

1. Open Chrome → navigate to `chrome://extensions/`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked** → select the `extension/` folder
4. The PhishGuard icon will appear in your toolbar

---

## 🧪 Testing

### Test URL Detection

With the backend running, try navigating to these URLs in Chrome:

| URL | Expected Result |
|-----|----------------|
| `https://www.google.com` | ✅ Safe — no warning |
| `https://github.com` | ✅ Safe — no warning |
| `http://secure-banking-login.com/verify` | 🚫 Blocked — warning page |
| `http://amaz0n-security.com/verify-account` | 🚫 Blocked — warning page |
| `http://192.168.1.100/paypal/login.php` | 🚫 Blocked — warning page |

### Test Gmail Email Detection

1. Open `https://mail.google.com` with the extension loaded
2. Open **DevTools Console** (F12) — look for `[PhishGuard Gmail]` logs
3. Send yourself test emails:

**Test 1 — Urgency phrases:**
> Subject: `Urgent: Verify your account immediately or it will be closed`
> Body: `Dear customer, we detected unauthorized activity. Confirm your identity within 24 hours.`

**Test 2 — Shortened URL:**
> Subject: `You have won a prize`
> Body: `Claim your reward: https://bit.ly/fake-link`

**Test 3 — Known phishing domain:**
> Subject: `Security Alert`
> Body: `Update your payment at http://secure-banking-login.com/verify`

Flagged emails will show a 🔴 **red left border** and a **"⚠ Phishing Risk" badge**. Hover the badge to see the specific reasons.

---

## 🏗️ Project Structure

```
Guardians-phishguard/
├── backend/
│   ├── datasets/
│   │   ├── phishing_urls.csv        # 208 URLs (106 safe + 101 phishing)
│   │   └── emails.csv               # ~488 emails (safe + phishing)
│   ├── main.py                      # FastAPI app — /predict & /analyze-email endpoints
│   ├── feature_extractor.py         # URL → 8 numerical features for ML
│   ├── train_model.py               # Training pipeline for both models
│   ├── email_analyzer.py            # TF-IDF email classifier module
│   ├── model.pkl                    # Trained URL classifier
│   ├── email_model.pkl              # Trained email classifier
│   ├── email_vectorizer.pkl         # TF-IDF vectorizer
│   └── requirements.txt            
│
├── extension/
│   ├── manifest.json                # Chrome Manifest V3 configuration
│   ├── background.js                # Service worker — URL interception & API calls
│   ├── content.js                   # General phishing warning banner (all sites)
│   ├── gmail_content.js             # Gmail-specific DOM scanner + backend ML calls
│   ├── phishing_domains.js          # 101 known phishing domains (auto-generated from dataset)
│   ├── popup.html / popup.js        # Extension popup — backend status check
│   ├── warning.html                 # Full-page phishing warning (blocked URLs)
│   ├── styles.css                   # Warning banner styles
│   ├── gmail_styles.css             # Gmail-specific styles (flagged rows, badges, tooltips)
│   └── icons/                       # Extension icons
│
└── frontend/
    ├── index.html                   # Cyberpunk-themed URL scanner dashboard
    ├── js/app.js                    # Frontend logic & Matrix-rain effects
    └── css/styles.css               # Terminal UI design system
```

---

## 🔌 API Endpoints

### `GET /`
Health check. Returns `{"status": "PhishGuard API is running"}`.

### `POST /predict`
Analyze a URL for phishing.

```json
// Request
{ "url": "http://secure-banking-login.com/verify" }

// Response
{
  "prediction": "phishing",
  "confidence": 87.5,
  "ml_probability": 0.723,
  "heuristic_score": 15
}
```

### `POST /analyze-email`
Analyze email content for phishing.

```json
// Request
{
  "subject": "Verify your account immediately",
  "sender": "security@paypal-verify.com",
  "snippet": "Dear customer, click here to confirm your identity..."
}

// Response
{
  "prediction": "phishing",
  "confidence": 92.3,
  "ml_probability": 0.923,
  "details": "ML classified as phishing with 92.3% confidence"
}
```

---

## 🧠 ML Features (URL Classifier)

The URL model extracts these 8 features from every URL:

| # | Feature | Example | Why It Matters |
|---|---------|---------|----------------|
| 1 | **URL Length** | `len("http://very-long-suspicious-url...")` = 78 | Phishing URLs tend to be longer |
| 2 | **Dot Count** | `"login.bank.verify.com"` → 3 dots | More subdomains = more suspicious |
| 3 | **Hyphen Count** | `"secure-login-verify"` → 2 hyphens | Phishers chain words with hyphens |
| 4 | **@ Symbol** | `"verify@account-update.xyz"` → 1 | Used to obscure the real destination |
| 5 | **IP Address** | `"192.168.1.1/login"` → True | Legitimate sites use domain names |
| 6 | **HTTPS** | `"http://..."` → False | Phishing sites often skip HTTPS |
| 7 | **Suspicious Words** | Contains "login", "verify", "bank" | Common in phishing URL paths |
| 8 | **Subdomain Count** | `"login.secure.bank.com"` → 2 | Excessive subdomains are suspicious |

---

## ⚠️ Known Limitations

- **Gmail DOM Selectors**: Gmail uses obfuscated CSS class names (e.g., `tr.zA`, `.y6 .bog`) that may change without notice. If the scanner stops detecting emails, the `SELECTORS` object in `gmail_content.js` will need updating.
- **Local Only**: The backend must be running on `localhost:8000` for ML features to work. If the backend is offline, the extension falls back to local heuristic-only detection.
- **Training Data Size**: The models are trained on relatively small datasets (~208 URLs, ~488 emails). Larger datasets would improve accuracy.

---

## 📚 Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python, FastAPI, Scikit-Learn, Joblib |
| ML Models | Logistic Regression, TF-IDF Vectorizer |
| Extension | Chrome Manifest V3, JavaScript, CSS |
| Frontend | HTML, CSS, JavaScript |
| Data | CSV datasets (phishing URLs + emails) |

---

## 🔄 Updating Datasets

To improve detection, add more entries to the CSV files:

1. **Add URLs** to `backend/datasets/phishing_urls.csv` — safe URLs use `https://`, phishing use `http://`
2. **Add emails** to `backend/datasets/emails.csv` — follow the 3-line pattern: `email text`, `Safe Email` or `Phishing Email`, `index`
3. **Re-train**: run `python train_model.py` — this retrains both models and auto-updates the extension's phishing domain list

---

**Developed by Team Guardians — University Cybersecurity Project 🎓**
