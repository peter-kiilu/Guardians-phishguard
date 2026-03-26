# PhishGuard 🛡️

PhishGuard is a comprehensive, real-time phishing detection system designed as a portfolio-ready cybersecurity project. It combines Machine Learning (Logistic Regression) and a Heuristic Engine to protect users from malicious URLs across multiple interfaces.

The project consists of three core components:

1.  **FastAPI Backend**: The brain of the system, handling URL feature extraction and ML prediction.
2.  **Chrome Extension**: A real-time browser monitor that intercepts malicious navigations before they load.
3.  **Cyberpunk Web Dashboard**: A standalone scanner for manual URL analysis with a high-fidelity visual interface.

---

## 🚀 Key Features

- **Real-time Interception**: Automatically blocks phishing URLs in the browser and redirects to a security warning page.
- **ML-Powered Detection**: Analyzes lexical features (URL length, subdomain count, suspicious keywords) using Scikit-Learn.
- **Heuristic Engine**: Scores URLs based on expert rules (suspicious TLDs like `.ru`, `.tk`, and IP-based hostnames).
- **Dual-Interface Analysis**: Monitor your browsing automatically with the extension or use the terminal-style web scanner.
- **Detailed Verdicts**: Provides transparency by showing Risk Scores, ML Probabilities, and Heuristic contributions.
- **Privacy-Focused**: Only the URL is processed for analysis; your personal page content is never read or stored.

---

## 🛠️ Setup Instructions

### 1. Backend Setup (The Engine)

Requires Python 3.8+.

```bash
# Navigate to backend directory
cd backend

# Install dependencies
pip install -r requirements.txt

# Train the ML model (generates model.pkl)
python train_model.py

# Start the FastAPI server
uvicorn main:app --reload
```

_The server will run at `http://localhost:8000`._

### 2. Frontend Setup (The Scanner)

Use a separate terminal to host the web dashboard on a custom port.

```bash
# Navigate to frontend directory
cd frontend

# Host the scanner dashboard on port 5500
python -m http.server 5500
```

_Access the dashboard at `http://localhost:5500`._

### 3. Extension Setup (The Shield)

1.  Open Chrome and navigate to `chrome://extensions/`.
2.  Enable **Developer mode** (toggle in the top right corner).
3.  Click **Load unpacked**.
4.  Select the `extension/` folder from this project.

---

## 🧪 Testing the Demo

Ensure the Backend is running, then test the protection using these examples:

- **Safe URLs**:
  - `https://www.google.com`
  - `https://github.com`
- **Phishing Examples** (Will trigger the Warning Page):
  - `http://secure-login-verify-account.tk`
  - `http://192.168.1.1/login.html`
  - `http://update-bank-info.ru/secure`

---

## 🏗️ Project Structure

### Backend (`/backend`)

- `main.py`: FastAPI application, API endpoints, and Heuristic Engine logic.
- `feature_extractor.py`: URL parser that converts strings into numerical ML features.
- `train_model.py`: Training script for the Logistic Regression model using synthetic data.
- `model.pkl`: The serialized ML model.

### Chrome Extension (`/extension`)

- `manifest.json`: Configuration for Chrome Manifest V3.
- `background.js`: Service worker that monitors URL changes and enforces security.
- `warning.html`: Full-page security warning displayed when a threat is intercepted.
- `popup.html`: Quick dashboard to check backend connectivity status.

### Web Dashboard (`/frontend`)

- `index.html`: High-fidelity Cyberpunk-themed URL scanner.
- `js/app.js`: Frontend logic for API communication and Matrix-rain visual effects.
- `css/styles.css`: Custom CSS design system for the futuristic terminal UI.

---

## 🛡️ Security & Performance

- **Proactive Blocking**: The system intercepts `onUpdated` events to protect users even on domains that don't exist yet.
- **Timeout Safety**: API calls are capped at 3 seconds to ensure browsing speed isn't compromised.
- **Local Processing**: Designed to run locally, ensuring data never leaves your machine.

---

**Developed for educational and demo purposes. Final project for University Cybersecurity Assignment.**
