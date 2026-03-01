# ============================================================
# ML-Based Phishing Prediction with Explainable AI (LightGBM + RFE)
# ============================================================

import os
import joblib
import shap
import numpy as np
from urllib.parse import urlparse
import warnings
warnings.filterwarnings("ignore")

# -------------------------------------------------
# Load model & RFE selector
# -------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "model")

MODEL_LOADED = False

try:
    model = joblib.load(os.path.join(MODEL_DIR, "phishing_model.pkl"))
    rfe = joblib.load(os.path.join(MODEL_DIR, "feature_selector.pkl"))
    FEATURE_NAMES = list(
        joblib.load(os.path.join(MODEL_DIR, "selected_features.pkl"))
    )
    MODEL_LOADED = True
except Exception as e:
    print("⚠️ Model load failed:", e)

# -------------------------------------------------
# Keyword lists
# -------------------------------------------------
SUSPICIOUS_WORDS = ["login", "verify", "secure", "account", "bank"]
BRAND_WORDS = ["paypal", "google", "amazon", "microsoft", "apple"]

# -------------------------------------------------
# Feature extraction
# -------------------------------------------------
def extract_features(url: str):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""

    features = [
        len(url),
        len(hostname),
        len(path),
        url.count("."),
        url.count("-"),
        url.count("@"),
        url.count("?"),
        url.count("="),
        url.count("/"),
        sum(c.isdigit() for c in url),
        int(url.startswith("https")),
        hostname.count(".") - 1 if hostname else 0,
        int(all(p.isdigit() for p in hostname.split(".")) if hostname else 0),
        int(any(w in url.lower() for w in SUSPICIOUS_WORDS)),
        int(any(b in url.lower() for b in BRAND_WORDS))
    ]

    return np.array([features])

# -------------------------------------------------
# SHAP explainer
# -------------------------------------------------
explainer = shap.TreeExplainer(model) if MODEL_LOADED else None

# -------------------------------------------------
# ML Prediction (SUPPORTING ONLY)
# -------------------------------------------------
def predict_phishing(url: str):
    """
    ML IS SUPPORTING SIGNAL ONLY
    - Never upgrades SAFE → PHISHING
    - Never downgrades heuristic PHISHING
    """

    if not MODEL_LOADED:
        return {
            "status": "suspicious",
            "confidence": 0.6,
            "detection_layer": "Machine Learning",
            "reasons": ["ML model unavailable"]
        }

    try:
        X = rfe.transform(extract_features(url))
        prob = model.predict_proba(X)[0][1]
    except Exception:
        return {
            "status": "suspicious",
            "confidence": 0.6,
            "detection_layer": "Machine Learning",
            "reasons": ["Feature selection failed"]
        }

    reasons = []
    try:
        shap_values = explainer.shap_values(X)
        shap_vals = shap_values[1][0] if isinstance(shap_values, list) else shap_values[0]
        for name, impact in sorted(
            zip(FEATURE_NAMES, shap_vals),
            key=lambda x: abs(x[1]),
            reverse=True
        )[:3]:
            if impact > 0:
                reasons.append(f"{name} increases phishing risk")
    except Exception:
        reasons.append("ML explanation unavailable")

    return {
        "status": "phishing" if prob >= 0.7 else "suspicious",
        "confidence": round(prob, 2),
        "detection_layer": "Machine Learning",
        "reasons": reasons or ["Statistical risk patterns detected"]
    }
