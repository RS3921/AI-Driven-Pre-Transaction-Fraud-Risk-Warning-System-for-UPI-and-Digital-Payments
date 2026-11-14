"""
Dual-Feed Intelligence Architecture for UPI Fraud Guard.

Feed 1: Transaction Intelligence (Metadata, velocity, sender/recipient patterns)
Feed 2: Threat Intelligence (Known malicious VPAs, reported fraud, phishing URLs, threat datasets)

Provides correlation, feed health monitoring, data validation, and graceful degradation.
"""
from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Set

logger = logging.getLogger("upi_fraud_guard.dual_feed")

_DATA_DIR = Path(__file__).resolve().parent / "data"
_REAL_URL_DIR = _DATA_DIR / "real_url_lists"


class ThreatIntelligenceFeed:
    """Feed 2: Threat Intelligence repository containing known malicious VPAs and URLs."""

    def __init__(self) -> None:
        self.last_updated: str = datetime.now(timezone.utc).isoformat()
        self.health_ok: Boolean = True
        self.suspicious_vpas: Set[str] = {
            "scammer@upi",
            "fakebank.collect@ybl",
            "lottery.winner@icici",
            "electricity.support@paytm",
            "reward.claim@axl",
            "cashback.offer@okaxis",
            "helpdesk.support@sbi",
            "customer.care.support@ybl",
            "kyc.update.refund@paytm",
        }
        self.phishing_urls: Set[str] = set()
        self._load_threat_data()

    def _load_threat_data(self) -> None:
        try:
            phish_file = _REAL_URL_DIR / "phishtank_feed.txt"
            if phish_file.exists():
                with open(phish_file, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip().lower()
                        if line and not line.startswith("#"):
                            self.phishing_urls.add(line)
            openphish_file = _REAL_URL_DIR / "openphish_feed.txt"
            if openphish_file.exists():
                with open(openphish_file, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip().lower()
                        if line and not line.startswith("#"):
                            self.phishing_urls.add(line)
            self.health_ok = True
            self.last_updated = datetime.now(timezone.utc).isoformat()
        except Exception as err:
            logger.warning(f"Could not load external threat files: {err}")
            self.health_ok = False

    def is_vpa_flagged(self, vpa: str) -> bool:
        if not vpa:
            return False
        clean_vpa = vpa.strip().lower()
        return clean_vpa in self.suspicious_vpas or any(kw in clean_vpa for kw in ["fake", "lottery", "helpdesk", "kyc.update"])

    def is_url_flagged(self, url: str) -> bool:
        if not url:
            return False
        clean_url = url.strip().lower()
        return any(phish in clean_url for phish in list(self.phishing_urls)[:2000]) if self.phishing_urls else False

    def add_threat_vpa(self, vpa: str) -> None:
        if vpa:
            self.suspicious_vpas.add(vpa.strip().lower())
            self.last_updated = datetime.now(timezone.utc).isoformat()

    def get_status(self) -> Dict[str, Any]:
        return {
            "name": "Threat Intelligence Feed",
            "healthy": self.health_ok,
            "vpa_threats_count": len(self.suspicious_vpas),
            "phishing_urls_count": len(self.phishing_urls),
            "last_updated": self.last_updated,
        }


class TransactionIntelligenceFeed:
    """Feed 1: Transaction Intelligence stream capturing behavioral and metadata features."""

    def __init__(self) -> None:
        self.health_ok: bool = True
        self.last_updated: str = datetime.now(timezone.utc).isoformat()

    def evaluate_transaction_context(
        self,
        amount: float | None,
        recipient: str | None,
        payments_last_hour: int | None,
        is_new_recipient: bool | None,
    ) -> Dict[str, Any]:
        risk_signals: List[str] = []
        score_multiplier = 0.0

        if amount is not None:
            if amount > 50000:
                risk_signals.append("High transaction amount (> ₹50,000)")
                score_multiplier += 0.35
            elif amount > 10000:
                risk_signals.append("Medium-high transaction amount (> ₹10,000)")
                score_multiplier += 0.15

        if is_new_recipient:
            risk_signals.append("First-time beneficiary transfer")
            score_multiplier += 0.25

        if payments_last_hour is not None:
            if payments_last_hour >= 5:
                risk_signals.append(f"High transaction velocity ({payments_last_hour} payments in last hour)")
                score_multiplier += 0.40
            elif payments_last_hour >= 3:
                risk_signals.append(f"Moderate transaction velocity ({payments_last_hour} payments in last hour)")
                score_multiplier += 0.20

        self.last_updated = datetime.now(timezone.utc).isoformat()
        return {
            "velocity_score": round(min(score_multiplier, 1.0), 3),
            "signals": risk_signals,
        }

    def get_status(self) -> Dict[str, Any]:
        return {
            "name": "Transaction Intelligence Feed",
            "healthy": self.health_ok,
            "last_updated": self.last_updated,
        }


class DualFeedEngine:
    """Correlates Transaction Feed and Threat Feed into a unified risk assessment."""

    def __init__(self) -> None:
        self.threat_feed = ThreatIntelligenceFeed()
        self.txn_feed = TransactionIntelligenceFeed()

    def correlate_check(
        self,
        vpa: str | None,
        url_or_qr: str | None,
        amount: float | None,
        payments_last_hour: int | None,
        is_new_recipient: bool | None,
    ) -> Dict[str, Any]:
        matched_indicators: List[str] = []
        threat_score = 0.0

        # Evaluate Threat Feed
        if vpa and self.threat_feed.is_vpa_flagged(vpa):
            matched_indicators.append(f"Recipient VPA '{vpa}' is listed in Threat Intelligence feed")
            threat_score += 0.85

        if url_or_qr and self.threat_feed.is_url_flagged(url_or_qr):
            matched_indicators.append("Link/URL is matched against Threat Intelligence phishing repository")
            threat_score += 0.80

        # Evaluate Transaction Feed
        txn_context = self.txn_feed.evaluate_transaction_context(amount, vpa, payments_last_hour, is_new_recipient)

        # Combined Feed Risk Calculation
        combined_score = min(1.0, threat_score + txn_context["velocity_score"] * 0.5)

        return {
            "combined_score": round(combined_score, 3),
            "threat_match_score": round(threat_score, 3),
            "velocity_score": txn_context["velocity_score"],
            "matched_indicators": matched_indicators + txn_context["signals"],
            "feed_status": {
                "threat_feed": self.threat_feed.get_status(),
                "transaction_feed": self.txn_feed.get_status(),
            },
        }


# Singleton instance
dual_feed_engine = DualFeedEngine()
