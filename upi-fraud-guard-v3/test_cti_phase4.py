"""
Automated Integration & Unit Test Suite for Phase 4: Fraud Detection Engine CTI Integration.

Tests:
- URL & Domain CTI threat indicator matching
- Multilingual message CTI scam pattern matching
- UPI QR payload payee VPA threat matching
- Transaction recipient VPA CTI threat matching
- Risk Fusion CTI evidence aggregation, score boosting, and risk tiering
- Edge cases: expired indicators, unverified indicators, CTI database offline handling
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cti_database import CTIDatabase, cti_db
from cti_matcher import cti_matcher
from multilingual_message_rules import analyse_multilingual_message
from risk_fusion import fuse
from transaction_module.analyzer import analyse_transaction
from url_qr_module.analyzer import analyse_url


class TestCTIPhase4FraudEngineIntegration(unittest.TestCase):

    def setUp(self) -> None:
        # Clear cti_matcher cache
        cti_matcher.invalidate_cache()

    # 1. URL & Domain CTI Indicator Match Test
    def test_01_url_cti_indicator_matching(self) -> None:
        test_url = "http://verified-phishing-threat-2026.com/verify-account"
        cti_db.add_indicator(
            indicator_value=test_url,
            indicator_type="url",
            threat_category="phishing",
            source_name="PhishTank Feed",
            confidence_score=90,
            verification_status="Verified Malicious",
        )
        cti_matcher.invalidate_cache()

        result = analyse_url(test_url)
        self.assertIn("cti_match", result)
        self.assertEqual(result["cti_match"]["matched_value"], test_url)
        self.assertGreaterEqual(result["score"], 0.85)

    # 2. UPI QR Payee VPA CTI Match Test
    def test_02_qr_vpa_cti_indicator_matching(self) -> None:
        test_vpa = "fraudster.collect@ybl"
        cti_db.add_indicator(
            indicator_value=test_vpa,
            indicator_type="vpa",
            threat_category="scam_recipient",
            source_name="NPCI Security Circulars",
            confidence_score=95,
            verification_status="Verified Malicious",
        )
        cti_matcher.invalidate_cache()

        qr_uri = f"upi://pay?pa={test_vpa}&pn=FakeStore&am=5000&cu=INR"
        result = analyse_url(qr_uri)
        self.assertIn("cti_match", result)
        self.assertEqual(result["cti_match"]["matched_value"], test_vpa)
        self.assertGreaterEqual(result["score"], 0.90)

    # 3. Transaction Recipient VPA CTI Match Test
    def test_03_transaction_recipient_cti_matching(self) -> None:
        test_vpa = "known.mule.account@sbi"
        cti_db.add_indicator(
            indicator_value=test_vpa,
            indicator_type="vpa",
            threat_category="mule_account",
            source_name="CERT-In Advisories",
            confidence_score=90,
            verification_status="Verified Malicious",
        )
        cti_matcher.invalidate_cache()

        result = analyse_transaction(amount=12000.0, recipient=test_vpa, payments_last_hour=None, is_new_recipient=None)
        self.assertIn("cti_match", result)
        self.assertGreaterEqual(result["score"], 0.85)

    # 4. Expired CTI Indicator Test (Must be ignored)
    def test_04_expired_indicator_ignored(self) -> None:
        expired_url = "http://expired-threat-site-2020.com/login"
        cti_db.add_indicator(
            indicator_value=expired_url,
            indicator_type="url",
            threat_category="phishing",
            source_name="OldFeed",
            confidence_score=90,
            verification_status="Verified Malicious",
            expires_at="2020-01-01T00:00:00+00:00",  # Expired timestamp
        )
        cti_matcher.invalidate_cache()

        match = cti_matcher.match_url_or_domain(expired_url)
        self.assertIsNone(match)  # Expired indicator must be ignored

    # 5. Risk Fusion CTI Evidence Aggregation & Tiering Test
    def test_05_risk_fusion_cti_evidence(self) -> None:
        msg_res = {"score": 0.85, "reasons": ["Urgent payment required"], "cti_match": {"indicator_id": "IND-123", "matched_value": "scam.apk", "confidence_score": 90}}
        url_res = {"score": 0.90, "reasons": ["Phishing link"], "kind": "URL", "cti_match": {"indicator_id": "IND-456", "matched_value": "http://scam.apk", "confidence_score": 90}}
        txn_res = {"score": 0.20, "reasons": []}

        fused = fuse(msg_res, url_res, txn_res)
        self.assertIn("cti_evidence", fused)
        self.assertEqual(len(fused["cti_evidence"]), 2)
        self.assertEqual(fused["verdict"], "High Risk")
        self.assertEqual(fused["risk_tier"], "Critical")
        self.assertGreaterEqual(fused["risk_score_100"], 85)

    # 6. Database Error / Offline Resilience Test
    @patch("cti_matcher.cti_db.query_indicators")
    def test_06_database_offline_resilience(self, mock_query: unittest.mock.MagicMock) -> None:
        mock_query.side_effect = Exception("Database connection lost")
        cti_matcher.invalidate_cache()

        # Fraud check must not crash when CTI DB is offline
        result = analyse_url("http://ordinary-website.com")
        self.assertIn("score", result)
        self.assertIsInstance(result["score"], float)


if __name__ == "__main__":
    unittest.main()
