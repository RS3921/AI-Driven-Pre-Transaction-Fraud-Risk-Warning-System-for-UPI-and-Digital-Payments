"""Local URL and QR-payload risk checks for the prototype.

Now model-backed: the risk score for a plain URL comes from a Random
Forest classifier trained on real phishing/legitimate URL data (see
train_model.py). The rule-based checks below are KEPT and still run --
they no longer set the score, but they generate the plain-language
"reasons" shown to the user, so the score is model-driven while the
explanation stays transparent and readable (a lightweight stand-in for
the SHAP-based explainability engine noted as a later phase in the
README, without needing that dependency yet).

UPI QR payloads (upi://...) aren't URLs at all -- they're structured
payment requests -- so those keep their own dedicated rule-based scoring
below; the ML model is specifically for http(s) links.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import urlparse

import joblib
import pandas as pd

from shap_explainability import explain_prediction
from url_qr_module.upi_qr import looks_like_upi_vpa, parse_upi_payment_uri, is_valid_upi_vpa

FEATURE_LABELS = {
    "url_length": "Overall link length",
    "num_dots": "Number of dots in the link",
    "num_hyphens": "Number of hyphens in the link",
    "num_digits": "Number of digits in the link",
    "num_subdomains": "Number of subdomains",
    "has_ip_address": "Uses a raw IP address instead of a domain",
    "has_at_symbol": "Contains an '@' symbol",
    "has_https": "Uses a secure HTTPS connection",
    "is_shortener": "Uses a link-shortening service",
    "has_suspicious_tld": "Domain ending commonly used by throwaway sites",
    "path_length": "Length of the link's path",
    "num_suspicious_keywords": "Number of banking/urgency keywords",
    "digit_ratio": "Proportion of the link made up of digits",
}

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.su", "shorturl.at", "cutt.ly", "rb.gy"}
# The bundled URL model has known false positives on several official payment
# domains. This small exact-root list is only a classifier correction; it is
# never used to trust the payee or to suppress clear link red flags.
KNOWN_PAYMENT_SITE_ROOTS = {"paytm.com", "phonepe.com", "npci.org.in", "bhimupi.org.in", "google.com"}
SUSPICIOUS_WORDS = {
    "verify", "login", "update", "secure", "kyc", "reward", "claim", "bonus",
    "wallet", "upi", "bank", "account", "password", "gift", "refund", "suspend",
}

_MODULE_DIR = Path(__file__).resolve().parent
_MODELS_DIR = _MODULE_DIR.parent / "models"
sys.path.insert(0, str(_MODULE_DIR))
from url_features import extract_features, FEATURE_NAMES  # noqa: E402

try:
    _url_model = joblib.load(_MODELS_DIR / "url_model.joblib")
except FileNotFoundError:
    _url_model = None  # falls back to a rule-based score below until `python setup.py` is run


def analyse_url(value: str) -> dict:
    """Score a URL or UPI QR payload. ML-backed for URLs; rule-based for UPI payloads."""
    value = (value or "").strip()
    reasons: list[str] = []
    if not value:
        return {"score": None, "reasons": [], "kind": None, "shap_explanation": []}

    if value.lower().startswith("upi://"):
        details = parse_upi_payment_uri(value)
        if details is None:
            return {
                "score": 0.78,
                "reasons": ["UPI payment QR has an invalid URI format"],
                "kind": "UPI QR payload",
                "upi_qr_details": None,
                "shap_explanation": [],
            }
        reasons.append("UPI payment request QR decoded; the payee identity is not independently verified")
        reasons.extend(details["flags"][:3])
        reasons.extend(details.get("notices", [])[:2])
        if not details["well_formed"]:
            score = 0.78
        elif details["flags"]:
            score = 0.42
        else:
            score = 0.12
        return {
            "score": score,
            "reasons": reasons,
            "kind": "UPI QR payload",
            "upi_qr_details": details,
            "shap_explanation": [],
        }

    # A standalone VPA is an account identifier, not a web address. Running
    # it through the phishing URL model treats its `@` as suspicious URL syntax
    # and creates false alarms for ordinary, valid UPI IDs. Syntax alone cannot
    # verify that the ID belongs to the person the user expects.
    if looks_like_upi_vpa(value):
        valid_shape = is_valid_upi_vpa(value)
        reason = (
            "UPI ID format recognized; this check cannot verify who owns the ID"
            if valid_shape
            else "This resembles a UPI ID, but its format could not be confirmed; verify it in your payment app"
        )
        return {
            "score": 0.02,
            "reasons": [reason],
            "kind": "UPI ID",
            "upi_qr_details": None,
            "shap_explanation": [],
        }

    candidate = value if "://" in value else f"https://{value}"
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").lower()
    path = f"{parsed.path}?{parsed.query}".lower()
    if not host:
        return {"score": 0.72, "reasons": ["Link format is invalid or missing a host"], "kind": "URL", "upi_qr_details": None, "shap_explanation": []}

    # --- Rule-based checks: kept as-is, but now feed only the "reasons" ---
    if parsed.scheme != "https":
        reasons.append("Link does not use HTTPS")
    if host in SHORTENERS:
        reasons.append("Shortened link hides its final destination")
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        reasons.append("Link uses a raw IP address instead of a domain")
    if "xn--" in host:
        reasons.append("Domain uses internationalised characters")
    if host.count("-") >= 2 or host.count(".") >= 3:
        reasons.append("Domain structure is unusually complex")
    hits = sorted(word for word in SUSPICIOUS_WORDS if word in f"{host}{path}")
    if hits:
        reasons.append(f"Link contains sensitive lure words: {', '.join(hits[:3])}")
    if len(value) > 100:
        reasons.append("Link is unusually long")

    root_match = next(
        (root for root in KNOWN_PAYMENT_SITE_ROOTS if host == root or host.endswith("." + root)),
        None,
    )
    has_clear_link_red_flag = (
        parsed.scheme != "https"
        or host in SHORTENERS
        or bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host))
        or "xn--" in host
        or host.count("-") >= 2
        or bool(hits)
        or len(value) > 100
    )
    if root_match and not has_clear_link_red_flag:
        # Do not let a memorized phishing-domain feature override a clean URL
        # on one of these recognized provider roots. This still cannot prove
        # that a particular payment request or payee is legitimate.
        return {
            "score": 0.08,
            "reasons": [f"HTTPS link uses the {root_match} domain; this does not verify the payment recipient"],
            "kind": "URL",
            "upi_qr_details": None,
            "shap_explanation": [],
        }

    # --- ML score: the trained model is the actual risk score now ---
    if _url_model is not None:
        row = pd.DataFrame([extract_features(candidate)])[FEATURE_NAMES]
        score = float(_url_model.predict_proba(row)[0][1])
        shap_explanation = explain_prediction("url_model.joblib", row, FEATURE_LABELS)
    else:
        score = min(0.98, 0.04 + 0.15 * len(reasons))  # fallback if model not yet trained
        shap_explanation = []

    if not reasons:
        reasons.append("No high-risk URL structure was detected")
    return {"score": round(min(score, 0.99), 3), "reasons": reasons, "kind": "URL", "upi_qr_details": None, "shap_explanation": shap_explanation}
