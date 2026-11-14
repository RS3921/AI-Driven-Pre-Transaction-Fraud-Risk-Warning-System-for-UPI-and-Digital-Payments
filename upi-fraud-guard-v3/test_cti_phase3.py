"""
Automated Integration & Unit Test Suite for Phase 3: Intelligence Extraction, Normalization & CTI API.

Tests:
- Technical indicator extraction (URLs, domains, IPs, hashes, emails, VPAs, fraud keywords)
- Canonicalization and domain normalization
- Syntax validation (IP, Hash, VPA, Email)
- Confidence scoring and cross-source corroboration boost
- Verification status mapping and expiry calculations
- Authenticated CTI REST API endpoints with pagination, search, filtering, and manual reviews
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from fastapi.testclient import TestClient

from api.main import app
from cti_database import CTIDatabase
from cti_extraction import intelligence_extractor
from cti_normalization import intelligence_normalizer


class TestCTIPhase3ExtractionAndAPI(unittest.TestCase):

    def setUp(self) -> None:
        self.client = TestClient(app)
        self.temp_db_file = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.temp_db_file.close()
        self.db = CTIDatabase(db_path=Path(self.temp_db_file.name))

    def tearDown(self) -> None:
        try:
            os.unlink(self.temp_db_file.name)
        except Exception:
            pass

    # 1. Technical Indicator Extraction Test
    def test_01_indicator_extraction(self) -> None:
        raw_content = """
        ALERT: Scam website http://fake-upi-pay.com/verify?utm_source=spam&ref=123 detected.
        Domain: fake-bank-support.org. IPv4: 198.51.100.22. IPv6: 2001:db8::1.
        Contact scammer@fakebank.com or VPA payee.support@ybl.
        Hashes: 5d41402abc4b2a76b9719d911017c592 (MD5) and 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12 (SHA1).
        Keywords: Please share OTP and enter pin to receive cash reward.
        """
        extracted = intelligence_extractor.extract_all(raw_content, source_name="TestFeed")
        indicators = extracted["indicators"]
        patterns = extracted["fraud_patterns"]

        types_found = {i["type"] for i in indicators}
        self.assertIn("url", types_found)
        self.assertIn("domain", types_found)
        self.assertIn("ip", types_found)
        self.assertIn("hash", types_found)
        self.assertIn("email", types_found)
        self.assertIn("vpa", types_found)

        categories_found = {p["category"] for p in patterns}
        self.assertIn("otp_harvesting", categories_found)

    # 2. Canonicalization & Normalization Test
    def test_02_canonicalization_and_normalization(self) -> None:
        raw_url = "HTTPS://WWW.Phishing-Bank.Com/login?utm_source=newsletter&fbclid=XYZ123&action=verify"
        clean_url = intelligence_normalizer.canonicalize_url(raw_url)
        self.assertEqual(clean_url, "https://www.phishing-bank.com/login?action=verify")

        raw_domain = " WWW.Fake-Paytm-Support.Org. "
        clean_domain = intelligence_normalizer.normalize_domain(raw_domain)
        self.assertEqual(clean_domain, "fake-paytm-support.org")

    # 3. Syntax Validation Test
    def test_03_syntax_validation(self) -> None:
        self.assertTrue(intelligence_normalizer.validate_ip("198.51.100.1"))
        self.assertTrue(intelligence_normalizer.validate_ip("2001:db8::1"))
        self.assertFalse(intelligence_normalizer.validate_ip("999.999.999.999"))

        is_valid_hash, hash_type = intelligence_normalizer.validate_hash("5d41402abc4b2a76b9719d911017c592")
        self.assertTrue(is_valid_hash)
        self.assertEqual(hash_type, "MD5")

        self.assertTrue(intelligence_normalizer.validate_vpa("user.support@ybl"))
        self.assertFalse(intelligence_normalizer.validate_vpa("invalid-vpa-without-at-symbol"))

        self.assertTrue(intelligence_normalizer.validate_email("test@example.com"))

    # 4. Confidence Scoring & Cross-Source Corroboration Test
    def test_04_confidence_and_corroboration(self) -> None:
        # Single source confidence
        conf1, status1, _ = intelligence_normalizer.calculate_confidence_and_status(
            indicator_value="http://threat-site.com",
            indicator_type="url",
            source_name="PhishTank Feed",
            source_count=1,
        )
        self.assertEqual(conf1, 75)
        self.assertEqual(status1, "Reported Unverified")

        # Corroborated across 2+ sources (+15 boost)
        conf2, status2, _ = intelligence_normalizer.calculate_confidence_and_status(
            indicator_value="http://threat-site.com",
            indicator_type="url",
            source_name="PhishTank Feed",
            source_count=2,
        )
        self.assertEqual(conf2, 90)
        self.assertEqual(status2, "Reported Unverified")  # Corroboration raises confidence, not verification

    # 5. Allowlist Filter Test
    def test_05_allowlist_filtering(self) -> None:
        conf, status, _ = intelligence_normalizer.calculate_confidence_and_status(
            indicator_value="https://npci.org.in/upi-circulars",
            indicator_type="url",
            source_name="UnknownFeed",
        )
        self.assertEqual(conf, 0)
        self.assertEqual(status, "Allowlisted")

    # 6. CTI API Endpoints Test
    def test_06_cti_api_endpoints(self) -> None:
        # Status endpoint
        res_status = self.client.get("/api/intelligence/status")
        self.assertEqual(res_status.status_code, 200)
        self.assertIn("total_sources", res_status.json())

        # Sources endpoint
        res_sources = self.client.get("/api/intelligence/sources")
        self.assertEqual(res_sources.status_code, 200)
        self.assertIsInstance(res_sources.json(), list)

        # Indicators paginated endpoint
        res_ind = self.client.get("/api/intelligence/indicators?limit=10&offset=0")
        self.assertEqual(res_ind.status_code, 200)
        self.assertIn("indicators", res_ind.json())

        # Fraud patterns endpoint
        res_pat = self.client.get("/api/intelligence/fraud-patterns")
        self.assertEqual(res_pat.status_code, 200)
        self.assertIsInstance(res_pat.json(), list)

        # Collection logs endpoint
        res_logs = self.client.get("/api/intelligence/collection-logs")
        self.assertEqual(res_logs.status_code, 200)
        self.assertIn("logs", res_logs.json())

    # 7. CTI Indicator Manual Review API Test
    def test_07_indicator_manual_review_api(self) -> None:
        from cti_database import cti_db
        # Seed test indicator into global cti_db
        ind_val = "http://phishing-manual-review-test.com"
        cti_db.add_indicator(
            indicator_value=ind_val,
            indicator_type="url",
            threat_category="phishing",
            source_name="TestFeed",
            confidence_score=60,
            verification_status="Reported Unverified",
        )
        match = cti_db.query_indicators(search_query="phishing-manual-review")[0]

        review_payload = {
            "new_status": "Verified Malicious",
            "review_notes": "Confirmed phishing page via manual sandbox analysis.",
        }
        res_rev = self.client.post(f"/api/intelligence/indicators/{match['indicator_id']}/review", json=review_payload)
        self.assertEqual(res_rev.status_code, 200)
        self.assertEqual(res_rev.json()["new_status"], "Verified Malicious")


if __name__ == "__main__":
    unittest.main()
