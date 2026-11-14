"""
Intelligence Normalization, Validation, Confidence Scoring & Corroboration Engine.

Canonicalizes URLs/Domains, validates IP/Hash/Email/VPA syntax, applies documented
confidence scoring rules, cross-source corroboration boosts, and expiration logic.
"""
from __future__ import annotations

import ipaddress
import re
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

ALLOWLISTED_DOMAINS = {
    "google.com", "yahoo.com", "microsoft.com", "github.com",
    "npci.org.in", "rbi.org.in", "cert-in.org.in", "cisa.gov",
    "paytm.com", "phonepe.com", "gpay.app", "sbi.co.in",
}

OFFICIAL_SOURCES = {
    "CERT-In Advisories", "NPCI Security Circulars", "RBI Fraud Awareness", "CISA Known Exploited Vulnerabilities"
}

TRACKING_QUERY_PARAMS = {"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "fbclid", "gclid", "ref"}


class IntelligenceNormalizer:
    """Normalizes indicator strings and calculates evidence-based confidence scores."""

    def canonicalize_url(self, url: str) -> str:
        """Canonicalizes URL by lowercasing scheme/host and stripping tracking parameters."""
        if not url:
            return ""
        parsed = urllib.parse.urlparse(url.strip())
        scheme = parsed.scheme.lower() if parsed.scheme else "http"
        netloc = parsed.netloc.lower()

        # Parse & filter query params
        query_params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        filtered_query = [(k, v) for k, v in query_params if k.lower() not in TRACKING_QUERY_PARAMS]
        clean_query = urllib.parse.urlencode(filtered_query)

        # Reconstruct canonical URL
        path = parsed.path if parsed.path else "/"
        canonical = urllib.parse.urlunparse((scheme, netloc, path, parsed.params, clean_query, ""))
        return canonical

    def normalize_domain(self, domain: str) -> str:
        """Normalizes domain by lowercasing and stripping trailing dots."""
        if not domain:
            return ""
        clean = domain.strip().lower().rstrip(".")
        if clean.startswith("www."):
            clean = clean[4:]
        return clean

    def validate_ip(self, ip_str: str) -> bool:
        """Validates IPv4 or IPv6 format using ipaddress module."""
        try:
            ipaddress.ip_address(ip_str.strip())
            return True
        except ValueError:
            return False

    def validate_hash(self, hash_str: str) -> Tuple[bool, str]:
        """Validates MD5, SHA-1, or SHA-256 hex string format."""
        clean = hash_str.strip().lower()
        if re.fullmatch(r"[a-f0-9]{32}", clean):
            return True, "MD5"
        if re.fullmatch(r"[a-f0-9]{40}", clean):
            return True, "SHA-1"
        if re.fullmatch(r"[a-f0-9]{64}", clean):
            return True, "SHA-256"
        return False, "Unknown"

    def validate_vpa(self, vpa_str: str) -> bool:
        """Validates UPI VPA syntax (username@handle)."""
        clean = vpa_str.strip().lower()
        return bool(re.fullmatch(r"[a-zA-Z0-9\.\-_]{2,50}@[a-zA-Z0-9]{2,20}", clean))

    def validate_email(self, email_str: str) -> bool:
        """Validates email syntax."""
        clean = email_str.strip().lower()
        return bool(re.fullmatch(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", clean))

    def calculate_confidence_and_status(
        self,
        indicator_value: str,
        indicator_type: str,
        source_name: str,
        base_confidence: Optional[int] = None,
        source_count: int = 1,
        collected_at_iso: Optional[str] = None,
        source_verified: bool = False,
    ) -> Tuple[int, str, Optional[str]]:
        """Calculates evidence-based confidence score, verification status, and expiry timestamp."""
        # Check allowlist
        clean_val = indicator_value.strip().lower()
        if clean_val.startswith("http://") or clean_val.startswith("https://"):
            host = urllib.parse.urlparse(clean_val).netloc.lower()
            if host.startswith("www."):
                host = host[4:]
            clean_val = host

        if any(clean_val == domain or clean_val.endswith("." + domain) for domain in ALLOWLISTED_DOMAINS):
            return 0, "Allowlisted", None

        # 1. Base confidence determination
        if base_confidence is not None:
            confidence = base_confidence
        elif source_name in OFFICIAL_SOURCES:
            confidence = 90
        else:
            confidence = 75

        # 2. Cross-source corroboration boost (+15 if reported across 2+ sources)
        if source_count >= 2:
            confidence = min(99, confidence + 15)

        # 3. Expiry Calculation
        now_dt = datetime.now(timezone.utc)
        lifespan_days = 30 if indicator_type == "ip" else 60 if indicator_type == "url" else 90
        collected_dt = now_dt
        if collected_at_iso:
            try:
                collected_dt = datetime.fromisoformat(collected_at_iso.replace("Z", "+00:00"))
                if collected_dt.tzinfo is None:
                    collected_dt = collected_dt.replace(tzinfo=timezone.utc)
            except ValueError:
                return 0, "Suspicious", None
        expires_at_dt = collected_dt + timedelta(days=lifespan_days)
        expires_at_iso = expires_at_dt.isoformat()
        if now_dt > expires_at_dt:
            return confidence, "Expired", expires_at_iso

        # High confidence and official provenance do not by themselves establish
        # that an indicator is malicious. Verification requires explicit source evidence.
        if source_verified:
            status = "Verified Malicious"
        elif confidence >= 40:
            status = "Reported Unverified"
        else:
            status = "Suspicious"
        return confidence, status, expires_at_iso


# Singleton instance
intelligence_normalizer = IntelligenceNormalizer()
