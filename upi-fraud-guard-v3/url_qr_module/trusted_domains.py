"""
Trusted Domain & False-Positive Mitigation Manager for AUIE.

Manages verified legitimate banking, payment gateway, government, and commercial domains,
distinguishes domain-level vs path-level reputation, handles IDN/Punycode normalization,
and protects against wildcard allowlist abuse.
"""
from __future__ import annotations

import logging
import re
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from cti_database import cti_db

logger = logging.getLogger("upi_fraud_guard.auie.trusted_domains")

# Fallback in-memory list of verified trusted domains
DEFAULT_TRUSTED_DOMAINS = {
    "google.com": {"category": "Search / Portal", "subdomains": True, "path_check": False},
    "paytm.com": {"category": "Payment Gateway", "subdomains": True, "path_check": False},
    "phonepe.com": {"category": "Payment Gateway", "subdomains": True, "path_check": False},
    "npci.org.in": {"category": "Financial Body", "subdomains": True, "path_check": False},
    "bhimupi.org.in": {"category": "Financial Body", "subdomains": True, "path_check": False},
    "sbi.co.in": {"category": "Bank", "subdomains": True, "path_check": False},
    "hdfcbank.com": {"category": "Bank", "subdomains": True, "path_check": False},
    "icicibank.com": {"category": "Bank", "subdomains": True, "path_check": False},
    "axisbank.com": {"category": "Bank", "subdomains": True, "path_check": False},
    "amazon.in": {"category": "E-Commerce", "subdomains": True, "path_check": False},
    "amazon.com": {"category": "E-Commerce", "subdomains": True, "path_check": False},
    "flipkart.com": {"category": "E-Commerce", "subdomains": True, "path_check": False},
    "github.com": {"category": "Developer Platform", "subdomains": True, "path_check": True},
    "medium.com": {"category": "Publishing Platform", "subdomains": True, "path_check": True},
    "swiggy.com": {"category": "Merchant", "subdomains": True, "path_check": False},
    "zomato.com": {"category": "Merchant", "subdomains": True, "path_check": False},
    "cert-in.org.in": {"category": "Government Advisory", "subdomains": True, "path_check": False},
    "rbi.org.in": {"category": "Regulatory Body", "subdomains": True, "path_check": False},
    "cisa.gov": {"category": "Government Advisory", "subdomains": True, "path_check": False},
    "microsoft.com": {"category": "Technology Platform", "subdomains": True, "path_check": False},
    "gpay.app": {"category": "Payment Gateway", "subdomains": True, "path_check": False},
}


class TrustedDomainManager:
    """Evaluates and manages trusted domain reputation to eliminate false positives."""

    def __init__(self) -> None:
        self._cache_timestamp = 0.0
        self._cached_domains: Dict[str, Dict[str, Any]] = {}

    def _get_trusted_map(self) -> Dict[str, Dict[str, Any]]:
        now = datetime.now(timezone.utc).timestamp()
        if now - self._cache_timestamp < 15.0 and self._cached_domains:
            return self._cached_domains

        trusted_map: Dict[str, Dict[str, Any]] = {}

        # 1. Start with in-memory defaults
        for d_name, meta in DEFAULT_TRUSTED_DOMAINS.items():
            trusted_map[d_name.lower()] = {
                "category": meta["category"],
                "allow_subdomains": meta["subdomains"],
                "requires_path_check": meta["path_check"],
                "source": "baseline_default",
            }

        # 2. Layer DB dynamic additions
        try:
            db_entries = cti_db.get_trusted_domains()
            current_dt = datetime.now(timezone.utc)
            for item in db_entries:
                domain = item["domain"].strip().lower()
                expires_at = item.get("expires_at")
                if expires_at:
                    try:
                        exp_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                        if exp_dt.tzinfo is None:
                            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                        if exp_dt <= current_dt:
                            continue
                    except ValueError:
                        pass
                trusted_map[domain] = {
                    "category": item.get("category", "Legitimate Domain"),
                    "allow_subdomains": bool(item.get("allow_subdomains", 1)),
                    "requires_path_check": bool(item.get("requires_path_check", 0)),
                    "source": "database",
                    "added_by": item.get("added_by", "system"),
                }
        except Exception as err:
            logger.warning("Error reading trusted domains from DB: %s", err)

        self._cached_domains = trusted_map
        self._cache_timestamp = now
        return self._cached_domains

    def invalidate_cache(self) -> None:
        self._cache_timestamp = 0.0

    @staticmethod
    def normalize_hostname(host: str) -> Tuple[str, str, bool]:
        """Normalizes hostname, handling IDN punycode (xn--). Returns (canonical_ascii, unicode_display, is_idn)."""
        clean_host = (host or "").strip().lower().rstrip(".")
        if clean_host.startswith("www."):
            clean_host = clean_host[4:]

        is_idn = "xn--" in clean_host
        unicode_host = clean_host
        ascii_host = clean_host

        if is_idn:
            try:
                # Decode punycode to unicode for display/matching
                unicode_host = clean_host.encode("ascii").decode("idna")
            except Exception:
                pass
        else:
            try:
                # Encode unicode domain to IDNA ascii
                ascii_host = clean_host.encode("idna").decode("ascii")
            except Exception:
                pass

        return ascii_host, unicode_host, is_idn

    def is_trusted(self, url_or_host: str) -> Optional[Dict[str, Any]]:
        """
        Checks if a URL or hostname belongs to a verified trusted domain.
        Returns match metadata if trusted, or None if unknown/unlisted.
        """
        if not url_or_host or not url_or_host.strip():
            return None

        clean = url_or_host.strip()
        if "://" in clean:
            parsed = urllib.parse.urlparse(clean)
            host = (parsed.hostname or "").lower()
            path = parsed.path or ""
        else:
            host = clean.split("/")[0].split(":")[0].lower()
            path = "/" + "/".join(clean.split("/")[1:]) if "/" in clean else ""

        ascii_host, unicode_host, is_idn = self.normalize_hostname(host)
        if not ascii_host:
            return None

        trusted_map = self._get_trusted_map()

        # Check exact host match first, then parent domain matches
        matched_domain = None
        matched_meta = None

        for domain, meta in trusted_map.items():
            if ascii_host == domain or unicode_host == domain:
                matched_domain = domain
                matched_meta = meta
                break
            if meta["allow_subdomains"]:
                if ascii_host.endswith("." + domain) or unicode_host.endswith("." + domain):
                    matched_domain = domain
                    matched_meta = meta
                    break

        if not matched_domain or not matched_meta:
            return None

        # Check path-level restriction for user-generated content domains (e.g., github.com/user)
        requires_path_check = matched_meta["requires_path_check"]
        if requires_path_check and path and path != "/":
            # If path contains explicit malicious indicators or raw script uploads, flag for review
            suspicious_path_patterns = [r"\.exe$", r"\.apk$", r"\.bat$", r"\.ps1$", r"/raw/"]
            for pat in suspicious_path_patterns:
                if re.search(pat, path, re.IGNORECASE):
                    return None  # Bypass domain trust for suspicious user-generated content path

        return {
            "matched_domain": matched_domain,
            "category": matched_meta["category"],
            "allow_subdomains": matched_meta["allow_subdomains"],
            "requires_path_check": matched_meta["requires_path_check"],
            "source": matched_meta.get("source", "trusted_manager"),
            "host": ascii_host,
            "is_idn": is_idn,
        }


trusted_domain_manager = TrustedDomainManager()
