# Backend Overview

The PhishGuard backend is built with **FastAPI** and serves as the core processing engine for the machine learning models. It receives URLs and email snippets from the Chrome extension, processes them, runs them through trained Scikit-Learn models, and returns phishing probability scores.

## Architecture

The backend consists of several key components:

- `main.py`: The FastAPI application that exposes the `/predict` and `/analyze-email` REST endpoints.
- `feature_extractor.py`: Handles the extraction of 8 numerical lexical features from raw URLs.
- `email_analyzer.py`: Handles the TF-IDF vectorization and classification of email content.
- `train_model.py`: The training pipeline script that reads datasets, trains the models, and saves them as `.pkl` files.

## Local Processing

For privacy reasons, the backend is designed to run completely on `localhost:8000`. No URLs or email contents are sent to external third-party servers. All machine learning inference happens directly on your machine.
