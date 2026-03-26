"""
PhishGuard — Model Training Script
====================================
Trains a phishing detection model using the Kaggle
'Web Page Phishing Detection' dataset (11,430 URLs, 87 features).

Dataset: shashwatwork/web-page-phishing-detection-dataset
Source:  https://www.kaggle.com/datasets/shashwatwork/web-page-phishing-detection-dataset

Usage:
    python train_model.py                     # Uses Kaggle dataset (auto-downloads)
    python train_model.py --local urls.csv    # Uses a local CSV of raw URLs (fallback)
"""

import os
import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline


# ──────────────────────────────────────────────
#  CONFIGURATION
# ──────────────────────────────────────────────

# Features we use from the Kaggle dataset.
# These are the columns most relevant to URL-level (lexical) phishing detection.
# We select a focused subset to keep the model interpretable and aligned with
# what our feature_extractor.py can also compute at inference time.
SELECTED_FEATURES = [
    "length_url",
    "length_hostname",
    "ip",
    "nb_dots",
    "nb_hyphens",
    "nb_at",
    "nb_qm",
    "nb_and",
    "nb_eq",
    "nb_underscore",
    "nb_slash",
    "nb_www",
    "nb_com",
    "nb_dslash",
    "http_in_path",
    "https_token",
    "ratio_digits_url",
    "ratio_digits_host",
    "punycode",
    "port",
    "tld_in_path",
    "tld_in_subdomain",
    "abnormal_subdomain",
    "nb_subdomains",
    "prefix_suffix",
    "shortening_service",
    "nb_redirection",
    "nb_external_redirection",
    "length_words_raw",
    "char_repeat",
    "longest_word_host",
    "longest_word_path",
    "avg_words_raw",
    "avg_word_host",
    "avg_word_path",
    "phish_hints",
    "suspecious_tld",
    "statistical_report",
]

KAGGLE_DATASET_PATH = os.path.expanduser(
    "~/.cache/kagglehub/datasets/shashwatwork/"
    "web-page-phishing-detection-dataset/versions/2/dataset_phishing.csv"
)


# ──────────────────────────────────────────────
#  DATA LOADING
# ──────────────────────────────────────────────

def load_kaggle_dataset():
    """Load the Kaggle phishing dataset. Auto-downloads if missing."""

    if not os.path.exists(KAGGLE_DATASET_PATH):
        print("  Dataset not found locally — downloading from Kaggle...")
        try:
            import kagglehub
            kagglehub.dataset_download("shashwatwork/web-page-phishing-detection-dataset")
        except Exception as e:
            raise FileNotFoundError(
                f"Could not download dataset: {e}\n"
                "Install kagglehub (pip install kagglehub) and ensure you "
                "have Kaggle credentials configured."
            )

    df = pd.read_csv(KAGGLE_DATASET_PATH)

    # Encode labels: legitimate → 0, phishing → 1
    df["label"] = (df["status"] == "phishing").astype(int)

    # Select only the features we want
    missing = [f for f in SELECTED_FEATURES if f not in df.columns]
    if missing:
        print(f"  ⚠ Missing columns (will be skipped): {missing}")
        features = [f for f in SELECTED_FEATURES if f in df.columns]
    else:
        features = SELECTED_FEATURES

    X = df[features].values
    y = df["label"].values

    return X, y, features


def load_local_dataset(csv_path):
    """Fallback: load a local CSV of raw URLs + extract features."""
    from feature_extractor import get_feature_vector

    urls = []
    with open(csv_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("label"):
                continue
            urls.append(line)

    X, y = [], []
    for url in urls:
        try:
            X.append(get_feature_vector(url))
            y.append(0 if url.startswith("https://") else 1)
        except Exception as e:
            print(f"  Skipping: {url[:50]}... — {e}")

    return np.array(X), np.array(y), None



#  TRAINING


def train_and_save(use_local=None):
    print("=" * 60)
    print("PHISHGUARD — MODEL TRAINING")
    print("=" * 60)

    # 1. Load data
    if use_local:
        print(f"\n[1/4] Loading local dataset: {use_local}")
        X, y, feature_names = load_local_dataset(use_local)
    else:
        print("\n[1/4] Loading Kaggle phishing dataset...")
        X, y, feature_names = load_kaggle_dataset()

    print(f"  Total samples: {len(X)}")
    print(f"  Features:      {X.shape[1]}")
    print(f"  Safe: {list(y).count(0)}  |  Phishing: {list(y).count(1)}")

    if len(X) == 0:
        print("ERROR: No data loaded.")
        return

    # 2. Train/Test split
    print("\n[2/4] Splitting data (80/20)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"  Train: {len(X_train)}  |  Test: {len(X_test)}")

    # 3. Cross-validation with two models
    print("\n[3/4] Cross-validating models (5-fold)...")

    models = {
        "Logistic Regression": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(max_iter=1000, random_state=42)),
        ]),
        "Random Forest": Pipeline([
            ("scaler", StandardScaler()),
            ("clf", RandomForestClassifier(
                n_estimators=100, random_state=42, n_jobs=-1
            )),
        ]),
    }

    best_name = None
    best_score = -1
    best_model = None

    for name, pipeline in models.items():
        scores = cross_val_score(pipeline, X_train, y_train, cv=5, scoring="f1")
        mean_f1 = scores.mean()
        print(f"  {name:25s} → F1: {mean_f1:.4f} ± {scores.std():.4f}")
        if mean_f1 > best_score:
            best_score = mean_f1
            best_name = name
            best_model = pipeline

    print(f"\n  ★ Best model: {best_name}")

    # 4. Final training + evaluation
    print("\n[4/4] Training final model & evaluating...")
    best_model.fit(X_train, y_train)

    y_pred = best_model.predict(X_test)
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Safe", "Phishing"]))
    print("Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(cm)
    print(f"\n  True Negatives  (safe→safe):     {cm[0][0]}")
    print(f"  False Positives (safe→phishing):  {cm[0][1]}")
    print(f"  False Negatives (phish→safe):     {cm[1][0]}")
    print(f"  True Positives  (phish→phishing): {cm[1][1]}")

    # Save model + feature list
    artifact = {
        "model": best_model,
        "model_name": best_name,
        "feature_names": feature_names,
        "n_features": X.shape[1],
        "train_samples": len(X_train),
        "test_accuracy": best_model.score(X_test, y_test),
    }
    joblib.dump(artifact, "model.pkl")

    print(f"\n{'=' * 60}")
    print(f" Model saved to model.pkl")
    print(f"   Model:          {best_name}")
    print(f"   Train accuracy:  {best_model.score(X_train, y_train):.4f}")
    print(f"   Test accuracy:   {best_model.score(X_test, y_test):.4f}")
    print(f"   Features used:   {X.shape[1]}")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 2 and sys.argv[1] == "--local":
        train_and_save(use_local=sys.argv[2])
    else:
        train_and_save()
