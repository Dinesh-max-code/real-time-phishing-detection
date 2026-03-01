# backend/openphish.py

import requests
import time

# -------------------------------------------------
# CONFIGURATION
# -------------------------------------------------
# Demo mode ENABLED by default (recommended for academic projects)
DEMO_MODE = True

# Controlled demo URLs (simulate OpenPhish hits)
DEMO_OPENPHISH_URLS = {
    "http://login.microsoftonline-support-security.com",
    "http://amazon-account-security-confirm.com",
    "http://secure-google-signin-alert.com"
}

# Live OpenPhish feed
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"

# Cache settings (only used in live mode)
CACHE_DURATION = 300  # seconds (5 minutes)
_cached_urls = set()
_last_fetch_time = 0

# -------------------------------------------------
# OpenPhish check function
# -------------------------------------------------
def check_openphish(url: str) -> bool:
    """
    Returns True if URL is detected as phishing by OpenPhish
    """

    global _cached_urls, _last_fetch_time

    # ================= DEMO MODE =================
    if DEMO_MODE:
        return url in DEMO_OPENPHISH_URLS

    # ================= LIVE MODE =================
    try:
        current_time = time.time()

        # Fetch feed only if cache expired
        if current_time - _last_fetch_time > CACHE_DURATION:
            response = requests.get(OPENPHISH_FEED_URL, timeout=10)
            response.raise_for_status()

            _cached_urls = set(response.text.splitlines())
            _last_fetch_time = current_time

        return url in _cached_urls

    except Exception as e:
        print("⚠️ OpenPhish unavailable:", e)
        return False
