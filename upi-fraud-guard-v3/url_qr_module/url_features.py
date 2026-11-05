"""
Shared lexical feature extraction for the URL/QR ML model.

Takes a raw URL string and turns it into numbers a classifier can learn
from -- the same "lexical features" approach used across the phishing-
URL-detection literature (see references 3, 11 in the project report):
things measurable just by looking at the URL text, with no need to
actually visit the site.

Imported by BOTH train_model.py and analyzer.py so features are computed
identically in training and at prediction time.
"""

import re
from urllib.parse import urlparse

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "goo.su", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorte.st", "rb.gy", "shorturl.at",
}
SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "info", "online", "site", "live", "work",
    "loan", "win", "gq", "tk", "ml", "cf", "icu",
}
SUSPICIOUS_KEYWORDS = [
    "verify", "login", "secure", "account", "update", "confirm", "kyc",
    "suspend", "block", "urgent", "bank", "upi", "refund", "reward",
    "cashback", "prize", "winner", "claim", "reactivate", "unlock", "wallet",
]
IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

FEATURE_NAMES = [
    "url_length", "num_dots", "num_hyphens", "num_digits", "num_subdomains",
    "has_ip_address", "has_at_symbol", "is_shortener",
    "has_suspicious_tld", "path_length", "num_suspicious_keywords", "digit_ratio",
]
# NOTE: "has_https" is deliberately EXCLUDED from the model's features.
# It used to be a useful phishing signal, but isn't anymore: free,
# automatic HTTPS (Let's Encrypt, Vercel, Cloudflare Pages, GitHub Pages,
# etc.) is now the DEFAULT for any site, phishing or not -- this is a
# well-documented shift in the phishing-detection literature. Including
# it here caused a real, measured problem: our older (~2013) legitimate-
# URL dataset predates widespread HTTPS adoption (0% HTTPS), while modern
# phishing URLs from free hosting are ~81% HTTPS -- purely a DATASET-AGE
# mismatch, not a real signal. Training on it made the model learn
# "HTTPS = risky", which is backwards, and it started flagging real
# sites like paytm.com as high risk. It's still checked and shown as a
# plain-language "reason" in analyzer.py (a non-HTTPS link is still
# worth a mention), just no longer feeds the model's score.


def extract_features(url: str) -> dict:
    url = (url or "").strip()
    parse_target = url if "://" in url else "http://" + url
    parsed = urlparse(parse_target)
    domain = parsed.netloc.lower().split(":")[0]
    path = parsed.path or ""

    domain_parts = domain.split(".") if domain else []
    tld = domain_parts[-1] if len(domain_parts) >= 2 else ""
    num_subdomains = max(len(domain_parts) - 2, 0)
    lower_url = url.lower()

    return {
        "url_length": len(url),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_digits": sum(c.isdigit() for c in url),
        "num_subdomains": num_subdomains,
        "has_ip_address": int(bool(IP_PATTERN.match(domain))),
        "has_at_symbol": int("@" in url),
        "has_https": int(url.lower().startswith("https://")),
        "is_shortener": int(domain in SHORTENER_DOMAINS),
        "has_suspicious_tld": int(tld in SUSPICIOUS_TLDS),
        "path_length": len(path),
        "num_suspicious_keywords": sum(kw in lower_url for kw in SUSPICIOUS_KEYWORDS),
        "digit_ratio": (sum(c.isdigit() for c in url) / len(url)) if url else 0.0,
    }
