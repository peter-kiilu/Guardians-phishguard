# Setup Instructions

## Prerequisites

- Python 3.8+
- Google Chrome
- Git

## 1. Clone & Install

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

## 2. Train the ML Models

```bash
cd backend
python train_model.py
```

This will load URLs and emails from the datasets, train both classifiers (`model.pkl` and `email_model.pkl`), and auto-update the Chrome extension's list of known phishing domains.

## 3. Start the Backend API

```bash
cd backend
python main.py
```

The API will run at `http://localhost:8000`. You can test it by visiting `http://localhost:8000/`.

## 4. Start the Web Dashboard (Optional)

```bash
cd frontend
python -m http.server 5500
```
Access the manual URL scanner dashboard at `http://localhost:5500`.

## 5. Load the Chrome Extension

1. Open Chrome → navigate to `chrome://extensions/`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked** → select the `extension/` folder
4. The PhishGuard icon will appear in your browser toolbar
