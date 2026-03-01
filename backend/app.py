from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse
import csv, os, unicodedata, re

from backend.phishtank import check_phishtank
from backend.openphish import check_openphish
from backend.ml_model import predict_phishing

from publicsuffix2 import get_sld

# =====================================================
# FASTAPI SETUP
# =====================================================
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# =====================================================
# CONFIGURATION
# =====================================================
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "update", "secure",
    "account", "alert", "confirm", "password", "support", "notification"
]

BRANDS = [
    "paypal", "google", "microsoft", "amazon",
    "apple", "appleid",
    "icici", "hdfc", "sbi", "bank"
]

OFFICIAL_BRAND_DOMAINS = {
    "google": ["google.com", "accounts.google.com"],
    "amazon": ["amazon.com"],
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "microsoftonline.com"],
    "icici": ["icicibank.com"],
    "sbi": ["sbi.co.in", "onlinesbi.com"],
    "rbi": ["rbi.org.in"],
    "gov": ["gov.in"]
}

COMMON_VALID_TLDS = {
    "com", "org", "net", "edu", "gov", "in", "uk", "us",
    "io", "co", "ai", "app", "dev", "me"
}

HOSTING_PLATFORMS = {
    "github.io", "netlify.app", "firebaseapp.com",
    "vercel.app", "herokuapp.com"
}
URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "buff.ly",
    "ow.ly",
    "cutt.ly"
}


SAFE_SUFFIXES = (
    ".bank.in", ".co.in", ".gov.in", ".nic.in", ".ac.in"
)

# =====================================================
# TRUSTED DOMAIN DATASET
# =====================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TRUSTED_FILE = os.path.join(BASE_DIR, "data", "trusted_domains.csv")

TRUSTED_DOMAINS = set()
try:
    with open(TRUSTED_FILE, newline="", encoding="utf-8") as f:
        for row in csv.reader(f):
            if row and "." in row[-1]:
                TRUSTED_DOMAINS.add(row[-1].strip().lower())
except Exception:
    pass

# =====================================================
# REQUEST MODEL
# =====================================================
class URLRequest(BaseModel):
    url: str

# =====================================================
# HELPER FUNCTIONS
# =====================================================
def hostname(url):
    return urlparse(url).hostname or ""

def registered_domain(url):
    return get_sld(hostname(url))

def is_ip_based_url(url):
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname(url)))

def is_official_brand_domain(url):
    host = hostname(url)
    for domains in OFFICIAL_BRAND_DOMAINS.values():
        if any(host == d or host.endswith("." + d) for d in domains):
            return True
    return False

def is_trusted_domain(url):
    rd = registered_domain(url)

    # 🔴 Never trust free hosting platforms
    if rd in HOSTING_PLATFORMS:
        return False

    # 🔴 Never trust URL shorteners
    if rd in URL_SHORTENERS:
        return False

    return rd in TRUSTED_DOMAINS



def brand_present(url):
    return any(b in url for b in BRANDS)

def credential_keywords_present(url):
    return any(k in url for k in SUSPICIOUS_KEYWORDS)

def is_free_hosting(url):
    return any(h in url for h in HOSTING_PLATFORMS)

def is_url_shortener(url):
    return registered_domain(url) in URL_SHORTENERS


def has_invalid_tld(url):
    return hostname(url).split(".")[-1] not in COMMON_VALID_TLDS

def looks_random_domain(url):
    name = hostname(url).split(".")[0]
    if len(name) < 7:
        return False
    vowels = set("aeiou")
    return (sum(c in vowels for c in name) / len(name)) < 0.25

def true_typosquatting(url):
    subs = {"0": "o", "1": "l", "3": "e", "5": "s", "7": "t"}
    normalized = url
    for k, v in subs.items():
        normalized = normalized.replace(k, v)
    return any(b in normalized and b not in url for b in BRANDS)

# =====================================================
# UNICODE / HOMOGLYPH DETECTION
# =====================================================
def normalize_unicode(text: str) -> str:
    return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii").lower()

def contains_non_ascii(text: str) -> bool:
    return any(ord(c) > 127 for c in text)

def is_homoglyph_attack(url):
    host = hostname(url)
    if host.endswith(SAFE_SUFFIXES):
        return False

    if contains_non_ascii(host):
        normalized = normalize_unicode(host)
        return any(b in normalized for b in BRANDS)

    return False

# =====================================================
# OFFICIAL / ORIGINAL SITE RESOLUTION (SAFE)
# =====================================================
def resolve_official_site(url: str):
    normalized = normalize_unicode(hostname(url))

    for brand, domains in OFFICIAL_BRAND_DOMAINS.items():
        if brand in normalized:
            return {
                "exists": True,
                "official_site": f"https://{domains[0]}",
                "confidence": "High",
                "method": "Known Brand Mapping"
            }

    return {
        "exists": False,
        "official_site": None,
        "confidence": None,
        "method": "Unavailable"
    }

# =====================================================
# MAIN API
# =====================================================
@app.post("/check-url")
def check_url(data: URLRequest):
    url = data.url.lower()
    impersonation = resolve_official_site(url)

    # 🔴 ABSOLUTE PHISHING
    if is_homoglyph_attack(url):
        return {
            "status": "phishing",
            "final_risk_score": 95,
            "impersonation": impersonation,
            "confidence_level": "High",
            "source": "Unicode Homoglyph Detection",
            "detection_layers": ["Heuristic"],
            "reasons": ["Homoglyph domain impersonation detected"]
        }

    if is_ip_based_url(url) and credential_keywords_present(url):
        return {
            "status": "phishing",
            "final_risk_score": 95,
            "impersonation": impersonation,
            "confidence_level": "High",
            "source": "IP-Based Phishing Detection",
            "detection_layers": ["Heuristic"],
            "reasons": ["Credential harvesting via IP-based URL"]
        }

    if check_phishtank(url) or check_openphish(url):
        return {
            "status": "phishing",
            "final_risk_score": 100,
            "impersonation": impersonation,
            "confidence_level": "High",
            "source": "Threat Intelligence",
            "detection_layers": ["Blacklist"],
            "reasons": ["Confirmed phishing URL"]
        }

    # 🟢 SAFE ZONE
        # 🟢 SAFE ZONE (STRICT – DO NOT TRUST FREE HOSTING)
    if is_official_brand_domain(url):
        return {
            "status": "safe",
            "final_risk_score": 5,
            "confidence_level": "Low",
            "source": "Official Brand Domain",
            "detection_layers": ["Whitelist"],
            "reasons": ["Verified official brand domain"]
        }

    if is_trusted_domain(url):
        return {
            "status": "safe",
            "final_risk_score": 5,
            "confidence_level": "Low",
            "source": "Trusted Dataset",
            "detection_layers": ["Whitelist"],
            "reasons": ["Domain present in trusted dataset"]
        }

    # National domains are safe ONLY if NOT free-hosted
    if hostname(url).endswith(SAFE_SUFFIXES) and not is_free_hosting(url):
        return {
            "status": "safe",
            "final_risk_score": 5,
            "confidence_level": "Low",
            "source": "National Trusted Domain",
            "detection_layers": ["Whitelist"],
            "reasons": ["Recognized government/banking domain"]
        }


    # 🔴 HIGH CONFIDENCE PHISHING
    if true_typosquatting(url) or (brand_present(url) and credential_keywords_present(url)):
        return {
            "status": "phishing",
            "final_risk_score": 90,
            "impersonation": impersonation,
            "confidence_level": "High",
            "source": "Brand Abuse Detection",
            "detection_layers": ["Heuristic"],
            "reasons": ["Brand impersonation with credential intent"]
        }

    if brand_present(url) and is_free_hosting(url):
        return {
            "status": "phishing",
            "final_risk_score": 90,
            "impersonation": impersonation,
            "confidence_level": "High",
            "source": "Free Hosting Abuse",
            "detection_layers": ["Heuristic"],
            "reasons": ["Brand hosted on free hosting platform"]
        }
    # 🔴 BRAND + SOCIAL ENGINEERING (NO LOGIN NEEDED)
    if brand_present(url) and any(k in url for k in ["help", "support", "customer", "service"]):
        return {
            "status": "phishing",
            "final_risk_score": 85,
            "impersonation": impersonation,
            "confidence_level": "High",
        "source": "Brand Social Engineering",
        "detection_layers": ["Heuristic"],
        "reasons": [
            "Brand impersonation detected",
            "Customer support themed phishing domain"
        ]
    }

    # 🔶 URL SHORTENER (SUSPICIOUS BY DEFAULT)
    if is_url_shortener(url):
        return {
        "status": "suspicious",
        "final_risk_score": 30,
        "impersonation": impersonation,
        "confidence_level": "Medium",
        "source": "URL Shortener Detection",
        "detection_layers": ["Heuristic"],
        "reasons": [
            "URL shortener hides the final destination",
            "Shortened links are commonly abused in phishing"
        ]
    }



    # 🔶 SUSPICIOUS
    score = 0
    reasons = []

    if has_invalid_tld(url):
        score += 40
        reasons.append("Invalid TLD")

    if looks_random_domain(url):
        score += 50
        reasons.append("Random-looking domain")

    if is_free_hosting(url):
        score += 30
        reasons.append("Free hosting usage")

    ml = predict_phishing(url)
    score = max(score, int(ml.get("confidence", 0) * 100))

    if score >= 40:
        return {
            "status": "suspicious",
            "final_risk_score": score,
            "impersonation": impersonation,
            "confidence_level": "Medium",
            "source": "Heuristic + ML",
            "detection_layers": ["Heuristic", "Machine Learning"],
            "reasons": reasons or ["Potential phishing indicators"]
        }

    # 🟢 DEFAULT SAFE
    return {
        "status": "safe",
        "final_risk_score": 10,
        "confidence_level": "Low",
        "source": "Risk Evaluation",
        "detection_layers": ["Baseline"],
        "reasons": ["No phishing indicators detected"]
    }
