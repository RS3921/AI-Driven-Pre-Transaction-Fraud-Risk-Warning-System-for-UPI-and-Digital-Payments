"""
Static Website Content Inspector & Safety Analyzer.

Safely inspects static HTML pages without executing JavaScript or binary downloads:
- Extracts page title, meta description, and form inputs
- Detects UPI PIN or OTP solicitation on web pages (Critical Fraud Indicator)
- Detects bank / financial institution brand impersonation
- Evaluates credential harvesting forms
"""
from __future__ import annotations

import logging
import re
import urllib.parse
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional

from cti_security import fetch_secure_content
from url_qr_module.trusted_domains import trusted_domain_manager

logger = logging.getLogger("upi_fraud_guard.auie.content_inspector")

KNOWN_FINANCIAL_BRANDS = {
    "sbi": ["state bank of india", "sbi", "onlinesbi"],
    "hdfc": ["hdfc bank", "netbanking.hdfcbank"],
    "icici": ["icici bank", "icicibank"],
    "paytm": ["paytm", "paytm wallet"],
    "phonepe": ["phonepe"],
    "gpay": ["google pay", "gpay"],
    "bhim": ["bhim", "bhim upi", "npci"],
    "income_tax": ["income tax department", "incometax.gov.in"],
}


class _StaticHTMLContentParser(HTMLParser):
    """Safe HTML parser that extracts title, meta description, forms, and input types."""

    def __init__(self) -> None:
        super().__init__()
        self.title: str = ""
        self.meta_description: str = ""
        self.in_title: bool = False
        self.forms_found: int = 0
        self.input_types: List[str] = []
        self.input_names: List[str] = []
        self.text_chunks: List[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        attr_dict = {k.lower(): (v or "").lower() for k, v in attrs}
        if tag.lower() == "title":
            self.in_title = True
        elif tag.lower() == "meta":
            if attr_dict.get("name") == "description":
                self.meta_description = attr_dict.get("content", "")
        elif tag.lower() == "form":
            self.forms_found += 1
        elif tag.lower() == "input":
            itype = attr_dict.get("type", "text").lower()
            iname = attr_dict.get("name", "").lower() + " " + attr_dict.get("placeholder", "").lower() + " " + attr_dict.get("id", "").lower()
            self.input_types.append(itype)
            self.input_names.append(iname)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title += data.strip() + " "
        elif data.strip():
            self.text_chunks.append(data.strip())


def inspect_website_content(url: str, domain: str) -> Dict[str, Any]:
    """
    Safely retrieves static HTML content (up to 512 KiB) and inspects title, forms, brand cues, and UPI PIN threats.
    """
    findings: List[Dict[str, Any]] = []
    has_upi_pin_threat = False
    has_otp_threat = False
    has_impersonation = False
    impersonated_brand = ""

    # Check if domain is an official trusted domain
    trusted_match = trusted_domain_manager.is_trusted(url)

    try:
        raw_bytes = fetch_secure_content(url, max_bytes=512 * 1024)
        html_text = raw_bytes.decode("utf-8", errors="replace")
    except Exception as fetch_err:
        logger.info("Content inspection skipped for '%s': %s", url, fetch_err)
        return {
            "inspected": False,
            "title": "",
            "meta_description": "",
            "forms_found": 0,
            "has_upi_pin_threat": False,
            "has_otp_threat": False,
            "has_impersonation": False,
            "findings": [{"type": "content_notice", "message": f"Static content inspection unavailable: {fetch_err}"}],
        }

    parser = _StaticHTMLContentParser()
    try:
        parser.feed(html_text)
    except Exception:
        pass

    page_title = parser.title.strip()
    page_desc = parser.meta_description.strip()
    combined_text = " ".join(parser.text_chunks + parser.input_names).lower()

    # 1. UPI PIN Solicitation Threat Inspection
    pin_patterns = [
        r"\bupi\s*pin\b", r"\benter\s*your\s*pin\b", r"\b4-digit\s*pin\b", r"\b6-digit\s*pin\b",
        r"\bupi\s*mpin\b", r"\benter\s*mpin\b"
    ]
    if any(re.search(pat, combined_text) for pat in pin_patterns):
        has_upi_pin_threat = True
        findings.append({
            "name": "UPI PIN Solicitation Threat",
            "finding": "Website page or form requests entry of a UPI PIN / MPIN",
            "why_it_matters": "CRITICAL THREAT: You should NEVER enter your UPI PIN on any website or web browser form. UPI PIN is strictly entered ONLY inside your official UPI mobile app (Google Pay, PhonePe, Paytm, BHIM) when authorizing a payment.",
            "source": "static_content_parser",
            "type": "confirmed",
            "contribution": "critical_risk_boost",
        })

    # 2. OTP Solicitation Threat Inspection
    otp_patterns = [r"\benter\s*otp\b", r"\bone\s*time\s*password\b", r"\benter\s*verification\s*code\b"]
    if any(re.search(pat, combined_text) for pat in otp_patterns) and not trusted_match:
        has_otp_threat = True
        findings.append({
            "name": "Unverified OTP Solicitation",
            "finding": "Unverified web page contains an OTP entry form",
            "why_it_matters": "Sharing OTPs on unverified websites allows fraudsters to perform unauthorized account takeovers or fund transfers.",
            "source": "static_content_parser",
            "type": "heuristic",
            "contribution": "high_risk_boost",
        })

    # 3. Brand Impersonation Inspection
    if not trusted_match:
        page_title_lower = page_title.lower()
        for brand_key, keywords in KNOWN_FINANCIAL_BRANDS.items():
            if any(kw in page_title_lower or kw in combined_text[:2000] for kw in keywords):
                has_impersonation = True
                impersonated_brand = brand_key.upper()
                findings.append({
                    "name": f"Financial Brand Impersonation ({impersonated_brand})",
                    "finding": f"Page content uses {impersonated_brand} brand name, but domain '{domain}' is not an official {impersonated_brand} domain",
                    "why_it_matters": "Phishing websites frequently copy official bank and payment portal branding to trick users into disclosing login credentials.",
                    "source": "brand_identity_inspector",
                    "type": "heuristic",
                    "contribution": "high_risk_boost",
                })
                break

    return {
        "inspected": True,
        "title": page_title[:200],
        "meta_description": page_desc[:300],
        "forms_found": parser.forms_found,
        "has_upi_pin_threat": has_upi_pin_threat,
        "has_otp_threat": has_otp_threat,
        "has_impersonation": has_impersonation,
        "impersonated_brand": impersonated_brand,
        "findings": findings,
    }
