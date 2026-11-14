"""
Intelligence Extraction Engine for Autonomous CTI Collection.

Extracts technical indicators (URLs, Domains, IPs, Hashes, Emails, VPAs)
and fraud patterns (Fake KYC, OTP harvesting, collect-request scams, QR scams, support impersonation)
from raw unstructured or structured threat intelligence content.
"""
from __future__ import annotations

import re
import urllib.parse
from typing import Any, Dict, List, Set

# Regex patterns for technical indicators
URL_PATTERN = re.compile(r"(?i)\bhttps?://[^\s<>'\"\(\)\[\]{}]+", re.IGNORECASE)
DOMAIN_PATTERN = re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.IGNORECASE)
IPV4_PATTERN = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
IPV6_PATTERN = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b")
HASH_MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
HASH_SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
HASH_SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
EMAIL_PATTERN = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
VPA_PATTERN = re.compile(r"\b[a-zA-Z0-9\.\-_]{2,50}@(ybl|okaxis|okhdfcbank|okicici|paytm|sbi|ibl|axl|barodampay|upi|idfcbank|icici|postbank|jupiteraxis)\b", re.IGNORECASE)

# Scam pattern categories and keywords
SCAM_CATEGORIES: Dict[str, List[str]] = {
    "kyc_fraud": ["kyc", "pan card update", "aadhaar link", "account blocked", "suspend account"],
    "otp_harvesting": ["share otp", "enter otp", "tell pin", "verification code", "otp expired"],
    "collect_request_scam": ["collect request", "approve request", "enter pin to receive", "request money"],
    "qr_replacement_scam": ["scan qr to receive", "qr payment reward", "scan to claim"],
    "impersonation_scam": ["customer care", "helpdesk", "bank support", "manager", "official support"],
    "remote_access_scam": ["anydesk", "teamviewer", "rustdesk", "quicksupport", "screen share"],
    "cashback_reward_scam": ["scratch card", "lottery winner", "cashback offer", "reward point"],
    "job_investment_scam": ["part time job", "telegram job", "work from home", "daily return", "crypto investment"],
}


class IntelligenceExtractor:
    """Extracts indicators and fraud patterns without executing or accessing external URLs."""

    def extract_all(self, content: str, source_name: str = "Unknown") -> Dict[str, Any]:
        """Parses text content and extracts technical indicators and recognized fraud patterns."""
        if not content or not isinstance(content, str):
            return {"indicators": [], "fraud_patterns": []}

        indicators: List[Dict[str, Any]] = []
        extracted_values: Set[str] = set()

        # 1. Extract URLs
        for match in URL_PATTERN.finditer(content):
            url_val = match.group(0).rstrip(".,;")
            if url_val.lower() not in extracted_values:
                extracted_values.add(url_val.lower())
                indicators.append({
                    "value": url_val,
                    "type": "url",
                    "category": "phishing",
                    "evidence": [f"Extracted URL from source {source_name}"],
                })

        # 2. Extract Domains (from non-URL text or extracted domains)
        for match in DOMAIN_PATTERN.finditer(content):
            dom_val = match.group(0).lower().rstrip(".")
            # Filter common false positives
            if dom_val not in extracted_values and not dom_val.endswith((".png", ".jpg", ".js", ".css", ".jsp", ".html", ".xml")):
                if "." in dom_val and len(dom_val.split(".")[-1]) >= 2:
                    extracted_values.add(dom_val)
                    indicators.append({
                        "value": dom_val,
                        "type": "domain",
                        "category": "phishing",
                        "evidence": [f"Extracted Domain from source {source_name}"],
                    })

        # 3. Extract IPv4
        for match in IPV4_PATTERN.finditer(content):
            ip_val = match.group(0)
            if ip_val not in extracted_values:
                extracted_values.add(ip_val)
                indicators.append({
                    "value": ip_val,
                    "type": "ip",
                    "category": "malicious_ip",
                    "evidence": [f"Extracted IPv4 address from source {source_name}"],
                })

        # 4. Extract IPv6
        for match in IPV6_PATTERN.finditer(content):
            ip_val = match.group(0)
            if ip_val.lower() not in extracted_values:
                extracted_values.add(ip_val.lower())
                indicators.append({
                    "value": ip_val,
                    "type": "ip",
                    "category": "malicious_ip",
                    "evidence": [f"Extracted IPv6 address from source {source_name}"],
                })

        # 5. Extract Hashes (SHA256, SHA1, MD5)
        for match in HASH_SHA256_PATTERN.finditer(content):
            h_val = match.group(0).lower()
            if h_val not in extracted_values:
                extracted_values.add(h_val)
                indicators.append({"value": h_val, "type": "hash", "category": "malware_hash", "evidence": ["SHA-256 Hash"]})

        for match in HASH_SHA1_PATTERN.finditer(content):
            h_val = match.group(0).lower()
            if h_val not in extracted_values and h_val not in [i["value"] for i in indicators if i["type"] == "hash"]:
                extracted_values.add(h_val)
                indicators.append({"value": h_val, "type": "hash", "category": "malware_hash", "evidence": ["SHA-1 Hash"]})

        for match in HASH_MD5_PATTERN.finditer(content):
            h_val = match.group(0).lower()
            if h_val not in extracted_values and h_val not in [i["value"] for i in indicators if i["type"] == "hash"]:
                extracted_values.add(h_val)
                indicators.append({"value": h_val, "type": "hash", "category": "malware_hash", "evidence": ["MD5 Hash"]})

        # 6. Extract Emails
        for match in EMAIL_PATTERN.finditer(content):
            em_val = match.group(0).lower()
            if em_val not in extracted_values:
                extracted_values.add(em_val)
                indicators.append({"value": em_val, "type": "email", "category": "phishing_sender", "evidence": ["Extracted Email"]})

        # 7. Extract VPAs
        for match in VPA_PATTERN.finditer(content):
            vpa_val = match.group(0).lower()
            if vpa_val not in extracted_values:
                extracted_values.add(vpa_val)
                indicators.append({"value": vpa_val, "type": "vpa", "category": "scam_recipient", "evidence": ["Extracted UPI VPA"]})

        # 8. Extract Fraud Patterns & Scam Categories
        extracted_patterns: List[Dict[str, Any]] = []
        content_lower = content.lower()
        for cat, keywords in SCAM_CATEGORIES.items():
            matched_kws = [kw for kw in keywords if kw in content_lower]
            if matched_kws:
                extracted_patterns.append({
                    "category": cat,
                    "matched_keywords": matched_kws,
                    "evidence": f"Found keywords: {', '.join(matched_kws)}",
                })

        return {
            "indicators": indicators,
            "fraud_patterns": extracted_patterns,
        }


# Singleton instance
intelligence_extractor = IntelligenceExtractor()
