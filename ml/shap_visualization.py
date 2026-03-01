import os
import joblib
import shap
import numpy as np
import matplotlib.pyplot as plt

# -----------------------------
# Load model & RFE
# -----------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "..", "backend", "model")

model = joblib.load(os.path.join(MODEL_DIR, "phishing_model.pkl"))
rfe = joblib.load(os.path.join(MODEL_DIR, "feature_selector.pkl"))
FEATURE_NAMES = list(joblib.load(os.path.join(MODEL_DIR, "selected_features.pkl")))

# -----------------------------
# Example URLs to explain
# -----------------------------
urls = [
    "https://paypa1-login-secure.com/account/verify",
    "https://www.amazon.in",
    "http://185.234.219.17/login"
]

# -----------------------------
# Feature extraction
# -----------------------------
from urllib.parse import urlparse

SUSPICIOUS_WORDS = ["login", "verify", "secure", "account", "bank"]
BRAND_WORDS = ["paypal", "google", "amazon", "microsoft", "apple"]

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

# -----------------------------
# SHAP explainer
# -----------------------------
explainer = shap.TreeExplainer(model)

for url in urls:
    X_full = extract_features(url)
    X_selected = rfe.transform(X_full)

    shap_values = explainer.shap_values(X_selected)
    shap_values_for_plot = shap_values[1][0] if isinstance(shap_values, list) else shap_values[0]

    # -----------------------------
    # Summary bar plot
    # -----------------------------
    shap.summary_plot(
        shap_values_for_plot.reshape(1, -1),
        features=X_selected,
        feature_names=FEATURE_NAMES,
        plot_type="bar",
        show=False
    )
    plt.title(f"SHAP Feature Impact: {url}")
    filename = url.replace("https://", "").replace("http://", "").replace("/", "_") + "_shap.png"
    plt.savefig(filename, bbox_inches='tight')
    plt.close()
    print(f"Saved SHAP plot: {filename}")
