"""Local URL and QR-payload risk checks for the prototype.

ML-backed for URLs; rule-based for UPI payloads; integrated with CTI threat indicators.
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
from cti_matcher import cti_matcher

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
    _url_model = None


def analyse_url(value: str) -> dict:
    """Score a URL or UPI QR payload. ML-backed for URLs; rule-based for UPI payloads."""
    value = (value or "").strip()
    reasons: list[str] = []
    if not value:
        return {"score": None, "reasons": [], "kind": None, "shap_explanation": []}

    # Query CTI Intelligence Engine
    cti_match = cti_matcher.match_url_or_domain(value)

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

        # Check VPA in CTI Threat Database
        vpa_cti_match = cti_matcher.match_vpa(details.get("payee_vpa") or "")
        if vpa_cti_match:
            reasons.append(f"CRITICAL: Payee VPA '{details.get('payee_vpa')}' is listed in Verified CTI Threat Database ({vpa_cti_match['source_name']})")
            score = 0.95
        elif not details["well_formed"]:
            score = 0.78
        elif details["flags"]:
            score = 0.42
        else:
            score = 0.12

        result_dict = {
            "score": score,
            "reasons": reasons,
            "kind": "UPI QR payload",
            "upi_qr_details": details,
            "shap_explanation": [],
        }
        if vpa_cti_match:
            result_dict["cti_match"] = vpa_cti_match
        return result_dict

    if looks_like_upi_vpa(value):
        valid_shape = is_valid_upi_vpa(value)
        vpa_cti_match = cti_matcher.match_vpa(value)
        if vpa_cti_match:
            reason = f"CRITICAL: UPI ID '{value}' matches verified malicious indicator in {vpa_cti_match['source_name']}"
            score = 0.92
        else:
            reason = (
                "UPI ID format recognized; this check cannot verify who owns the ID"
                if valid_shape
                else "This resembles a UPI ID, but its format could not be confirmed; verify it in your payment app"
            )
            score = 0.02

        res = {
            "score": score,
            "reasons": [reason],
            "kind": "UPI ID",
            "upi_qr_details": None,
            "shap_explanation": [],
        }
        if vpa_cti_match:
            res["cti_match"] = vpa_cti_match
        return res

    # Upgrade URL evaluation with Adaptive URL Intelligence Engine (AUIE)
    from url_qr_module.auie_engine import auie_engine

    auie_res = auie_engine.evaluate_url(value)
    candidate = auie_res["canonical_url"] or (value if "://" in value else f"https://{value}")

    # Compute SHAP explainability if url_model is loaded
    shap_explanation = []
    if _url_model is not None and auie_res["domain"]:
        try:
            row = pd.DataFrame([extract_features(candidate)])[FEATURE_NAMES]
            shap_explanation = explain_prediction("url_model.joblib", row, FEATURE_LABELS)
        except Exception:
            shap_explanation = []

    out_res = {
        "score": auie_res["risk_score"],
        "reasons": auie_res["reasons"],
        "kind": "URL",
        "reputation_state": auie_res["reputation_state"],
        "confidence_score": auie_res["confidence_score"],
        "canonical_url": auie_res["canonical_url"],
        "domain": auie_res["domain"],
        "sources_evidence": auie_res["sources_evidence"],
        "conflicting_evidence": auie_res["conflicting_evidence"],
        "providers_consulted": auie_res["providers_consulted"],
        "upi_qr_details": None,
        "shap_explanation": shap_explanation,
    }
    if cti_match:
        out_res["cti_match"] = cti_match
    return out_res
