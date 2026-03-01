# backend/phishtank.py

import requests

# -------------------------------------------------
# CONFIGURATION
# -------------------------------------------------
# Demo mode is ENABLED by default (recommended for academic projects)
DEMO_MODE = True

# Controlled demo URLs (simulate PhishTank hits)
DEMO_PHISHTANK_URLS = {
    "http://secure-paypal-account-update-login.com",
    "http://appleid-verify-support-login.com",
    "http://paypal-verification-center-login.com"
}

# Optional (real PhishTank requires API key – not reliable for demo)
PHISHTANK_API_URL = "https://data.phishtank.com/data/online-valid.json"

# -------------------------------------------------
# PhishTank check function
# -------------------------------------------------
def check_phishtank(url: str) -> bool:
    """
    Returns True if URL is detected as phishing by PhishTank
    """

    # ================= DEMO MODE =================
    if DEMO_MODE:
        return url in DEMO_PHISHTANK_URLS

    # ================= REAL MODE (NOT RECOMMENDED) =================
    try:
        response = requests.get(PHISHTANK_API_URL, timeout=10)
        response.raise_for_status()

        data = response.json()

        for entry in data:
            if url == entry.get("url"):
                return True

        return False

    except Exception as e:
        print("⚠️ PhishTank unavailable:", e)
        return False
