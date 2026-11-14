"""Matches only explicitly verified, active, non-quarantined CTI indicators."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cti_database import cti_db
from cti_normalization import intelligence_normalizer

logger = logging.getLogger("upi_fraud_guard.cti_matcher")

class CTIMatcher:
    def __init__(self) -> None:
        self._cache_timestamp = 0.0
        self._cached_verified_indicators: List[Dict[str, Any]] = []

    def _get_verified_indicators(self) -> List[Dict[str, Any]]:
        now = datetime.now(timezone.utc).timestamp()
        if now - self._cache_timestamp < 30.0:
            return self._cached_verified_indicators
        try:
            indicators = cti_db.query_indicators(verification_status="Verified Malicious", limit=1_000_000)
            current = datetime.now(timezone.utc)
            active = []
            for item in indicators:
                if item.get("quarantined"):
                    continue
                if item.get("verification_status") != "Verified Malicious":
                    continue
                expires = item.get("expires_at")
                if expires:
                    try:
                        expiry_dt = datetime.fromisoformat(expires.replace("Z", "+00:00"))
                        if expiry_dt.tzinfo is None:
                            expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
                        if expiry_dt <= current:
                            continue
                    except ValueError:
                        continue
                active.append(item)
            self._cached_verified_indicators = active
            self._cache_timestamp = now
        except Exception as err:
            logger.warning("Error querying CTI indicators from database: %s", err)
        return self._cached_verified_indicators

    def invalidate_cache(self, indicator_id: Optional[str] = None) -> None:
        # Cache is intentionally invalidated wholesale: review/revocation may change
        # the status of an indicator that was already cached as a positive match.
        self._cache_timestamp = 0.0

    def match_url_or_domain(self, input_str: str) -> Optional[Dict[str, Any]]:
        if not input_str or not input_str.strip():
            return None
        clean = input_str.strip().lower()
        canonical = intelligence_normalizer.canonicalize_url(clean) if clean.startswith(("http://", "https://")) else clean
        domain = intelligence_normalizer.normalize_domain(clean)
        for ind in self._get_verified_indicators():
            value = ind["indicator_value"].strip().lower()
            kind = ind["indicator_type"]
            if kind == "url" and canonical and value == canonical:
                return self._build_match_result(ind, "Exact verified URL match", "url_qr")
            if kind in ("domain", "url"):
                candidate = intelligence_normalizer.normalize_domain(value) if kind == "url" else value
                if domain and candidate and (domain == candidate or domain.endswith("." + candidate)):
                    return self._build_match_result(ind, f"Verified domain match '{candidate}'", "url_qr")
        return None

    def match_vpa(self, vpa_str: str) -> Optional[Dict[str, Any]]:
        if not vpa_str or not vpa_str.strip():
            return None
        value = vpa_str.strip().lower()
        for ind in self._get_verified_indicators():
            if ind["indicator_type"] == "vpa" and ind["indicator_value"].strip().lower() == value:
                return self._build_match_result(ind, "Recipient VPA is an active verified indicator", "transaction")
        return None

    def match_message_patterns(self, message_str: str) -> Optional[Dict[str, Any]]:
        if not message_str or not message_str.strip():
            return None
        clean = message_str.strip().lower()
        for ind in self._get_verified_indicators():
            value = ind["indicator_value"].strip().lower()
            if len(value) >= 4 and value in clean:
                return self._build_match_result(ind, "Message contains an active verified indicator", "message")
        return None

    @staticmethod
    def _build_match_result(ind: Dict[str, Any], reason: str, module: str) -> Dict[str, Any]:
        return {
            "indicator_id": ind["indicator_id"], "indicator_type": ind["indicator_type"],
            "matched_value": ind["indicator_value"], "threat_category": ind["threat_category"],
            "verification_status": ind["verification_status"], "source_name": ind["source_name"],
            "confidence_score": ind["confidence_score"], "first_seen": ind["first_seen"],
            "evidence_reference": ind.get("source_reference", ""), "match_reason": reason, "module": module,
        }

cti_matcher = CTIMatcher()
