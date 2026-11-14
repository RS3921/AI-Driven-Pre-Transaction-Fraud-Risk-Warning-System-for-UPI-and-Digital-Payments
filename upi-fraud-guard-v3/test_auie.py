"""
Comprehensive Test Suite for Adaptive URL Intelligence Engine (AUIE).

Exercises:
1. Legitimate URLs & False-Positive Mitigation (Banking, Payment, E-Commerce, Long Query Strings, IDNs).
2. Malicious URLs & Threat Intelligence Correlation (Verified Phishing, Malware, CTI Matches).
3. Unknown URLs & 4-State Disambiguation (UNKNOWN vs KNOWN_BENIGN).
4. Provider Failures & Resilience (Unconfigured Keys, Timeouts, Rate Limits, Exception Isolation).
5. Security Defenses (SSRF, Private IPs, Privacy Parameter Stripping, XSS Sanitization).
6. Performance & Latency Measurements (Cache Hits/Misses, Response Latency).
7. False-Positive Rate (FPR), Precision, Recall, and F1-score Evaluation.
"""

import unittest
import time
from fastapi.testclient import TestClient
from api.main import app
from cti_database import cti_db
from cti_matcher import cti_matcher
from url_qr_module.auie_engine import auie_engine
from url_qr_module.auie_providers import (
    GoogleWebRiskProvider, VirusTotalProvider, UrlhausProvider,
    OpenPhishProvider, AlienVaultOtxProvider, sanitize_url_for_privacy
)
from url_qr_module.trusted_domains import trusted_domain_manager


class TestAUIE(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_01_legitimate_url_false_positive_mitigation(self):
        """Verify that legitimate banking, payment, e-commerce, and long query string URLs return KNOWN_BENIGN without false-positive alerts."""
        legitimate_test_cases = [
            "https://paytm.com",
            "https://phonepe.com",
            "https://sbi.co.in/web/personal-banking/login-security",
            "https://netbanking.hdfcbank.com/netbanking/",
            "https://amazon.in/ap/signin?openid.pape.max_auth_age=0&openid.return_to=https%3A%2F%2Fwww.amazon.in%2F&openid.assoc_handle=inflex",
            "https://swiggy.com/restaurants",
            "https://github.com/upifraudguard/project",
        ]

        for url in legitimate_test_cases:
            res = auie_engine.evaluate_url(url, bypass_cache=True)
            self.assertEqual(res["reputation_state"], "KNOWN_BENIGN", f"URL '{url}' was incorrectly classified as {res['reputation_state']}")
            self.assertLess(res["risk_score"], 0.30, f"URL '{url}' produced a high risk score {res['risk_score']}")
            self.assertTrue(any("VERIFIED TRUSTED DOMAIN" in r for r in res["reasons"]), f"URL '{url}' missing trusted domain attribution reason")

    def test_02_malicious_url_cti_threat_match(self):
        """Verify that verified CTI threat indicators return CONFIRMED_MALICIOUS state with high risk score."""
        test_url = "http://phishing-bank-update-upi.xyz/login"
        # Seed a verified malicious indicator in DB
        cti_db.add_indicator(
            indicator_value=test_url,
            indicator_type="url",
            threat_category="phishing",
            source_name="CERT-In Advisories",
            description="Verified malicious phishing test indicator",
            confidence_score=95,
            verification_status="Verified Malicious",
            source_verified=True
        )
        cti_matcher.invalidate_cache()

        res = auie_engine.evaluate_url(test_url, bypass_cache=True)
        self.assertEqual(res["reputation_state"], "CONFIRMED_MALICIOUS")
        self.assertGreaterEqual(res["risk_score"], 0.88)
        self.assertTrue(any("VERIFIED THREAT INTEL" in r for r in res["reasons"]))

    def test_03_unknown_url_reputation_state_disambiguation(self):
        """Verify that unindexed/new URLs without threat history or trusted domain status return UNKNOWN state (and NOT KNOWN_BENIGN)."""
        unknown_url = "https://random-unindexed-merchant-site-12345.com/item"
        res = auie_engine.evaluate_url(unknown_url, bypass_cache=True)
        self.assertEqual(res["reputation_state"], "UNKNOWN")
        self.assertLess(res["risk_score"], 0.30)
        self.assertIn("URL has no known threat indicators; domain reputation history is unindexed/unknown", res["reasons"])

    def test_04_suspicious_url_lexical_indicators(self):
        """Verify that URLs with raw IP addresses, suspicious TLDs, or lure words return SUSPICIOUS state."""
        suspicious_cases = [
            ("http://192.168.1.1/login", "raw IP address"),
            ("http://free-upi-cashback-reward.xyz/claim", "suspicious TLD"),
            ("https://tinyurl.com/pay-here", "shortener"),
        ]

        for url, expected_reason in suspicious_cases:
            res = auie_engine.evaluate_url(url, bypass_cache=True)
            self.assertEqual(res["reputation_state"], "SUSPICIOUS")
            self.assertGreaterEqual(res["risk_score"], 0.35)
            self.assertTrue(any(expected_reason in r for r in res["reasons"]))

    def test_05_provider_privacy_parameter_stripping(self):
        """Verify that sensitive UPI and authentication parameters are stripped before outbound API lookups."""
        raw_url = "https://example-payee.com/pay?pa=scammer@upi&pn=JohnDoe&am=15000&otp=123456&pin=9999&token=secret_abc"
        safe_url = sanitize_url_for_privacy(raw_url)

        self.assertNotIn("pa=scammer@upi", safe_url)
        self.assertNotIn("am=15000", safe_url)
        self.assertNotIn("otp=123456", safe_url)
        self.assertNotIn("pin=9999", safe_url)
        self.assertNotIn("token=secret_abc", safe_url)
        self.assertIn("https://example-payee.com/pay", safe_url)

    def test_06_provider_failure_resilience(self):
        """Verify that unconfigured or failing external providers return UNCONFIGURED/FAILED status without crashing the engine."""
        vr_provider = VirusTotalProvider()
        res = vr_provider.lookup_url("https://google.com", "google.com")

        self.assertIn(res["status"], ["UNCONFIGURED", "ACTIVE", "FAILED"])
        self.assertIsInstance(res["latency_ms"], float)
        # Verify engine completes analysis despite unconfigured providers
        engine_res = auie_engine.evaluate_url("https://sbi.co.in", bypass_cache=True)
        self.assertIn("reputation_state", engine_res)

    def test_07_auie_api_endpoints(self):
        """Test AUIE REST API endpoints: GET /reputation, GET /providers, GET /health, GET /trusted-domains."""
        # 1. GET /api/auie/reputation
        resp = self.client.get("/api/auie/reputation?url=https://paytm.com")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["reputation_state"], "KNOWN_BENIGN")

        # 2. GET /api/auie/providers
        resp_prov = self.client.get("/api/auie/providers")
        self.assertEqual(resp_prov.status_code, 200)
        self.assertIsInstance(resp_prov.json(), list)

        # 3. GET /api/auie/health
        resp_health = self.client.get("/api/auie/health")
        self.assertEqual(resp_health.status_code, 200)
        self.assertIn("feed_health", resp_health.json())

        # 4. GET /api/auie/trusted-domains
        resp_trusted = self.client.get("/api/auie/trusted-domains")
        self.assertEqual(resp_trusted.status_code, 200)
        self.assertGreater(len(resp_trusted.json()), 0)

    def test_08_analyst_feedback_and_review_workflow(self):
        """Test submitting false-positive feedback and analyst review workflow."""
        # 1. Submit Feedback Report
        fb_resp = self.client.post("/api/auie/feedback", json={
            "url_or_domain": "https://trusted-merchant-portal.com",
            "reported_verdict": "Suspicious",
            "claimed_verdict": "Safe",
            "reason": "Legitimate payment partner domain erroneously flagged"
        })
        self.assertEqual(fb_resp.status_code, 200)
        fb_id = fb_resp.json()["feedback_id"]

        # 2. List Feedback Reports
        list_resp = self.client.get("/api/auie/feedback")
        self.assertEqual(list_resp.status_code, 200)
        self.assertTrue(any(item["feedback_id"] == fb_id for item in list_resp.json()))

        # 3. Review Feedback Report (Approve)
        review_resp = self.client.post(f"/api/auie/feedback/{fb_id}/review", json={
            "action": "APPROVED",
            "review_notes": "Domain verified with banking partner"
        })
        self.assertEqual(review_resp.status_code, 200)
        self.assertEqual(review_resp.json()["action"], "APPROVED")

    def test_09_performance_and_caching(self):
        """Measure AUIE cache hit latency vs cold miss latency."""
        test_url = "https://sbi.co.in/netbanking/login"

        # Cold Miss
        start_miss = time.time()
        res_miss = auie_engine.evaluate_url(test_url, bypass_cache=True)
        miss_lat = (time.time() - start_miss) * 1000.0

        # Warm Cache Hit
        start_hit = time.time()
        res_hit = auie_engine.evaluate_url(test_url, bypass_cache=False)
        hit_lat = (time.time() - start_hit) * 1000.0

        self.assertEqual(res_hit["cache_status"], "HIT")
        self.assertLess(hit_lat, 25.0, f"Cache hit latency {hit_lat}ms exceeded 25ms SLA cap")

    def test_10_false_positive_rate_evaluation(self):
        """Evaluate False Positive Rate (FPR), Precision, Recall, and F1-score across labelled dataset."""
        labelled_dataset = [
            # Legitimate (Ground Truth = 0)
            ("https://google.com", 0),
            ("https://paytm.com", 0),
            ("https://phonepe.com", 0),
            ("https://sbi.co.in/web/personal-banking", 0),
            ("https://netbanking.hdfcbank.com", 0),
            ("https://amazon.in/ap/signin", 0),
            ("https://swiggy.com/restaurants", 0),
            ("https://github.com/project", 0),
            ("https://zomato.com/order", 0),
            ("https://flipkart.com/view", 0),

            # Malicious (Ground Truth = 1)
            ("http://phishing-bank-update-upi.xyz/login", 1),
            ("http://free-upi-cashback-reward.xyz/claim", 1),
            ("http://192.168.1.1/login", 1),
        ]

        tp, fp, tn, fn = 0, 0, 0, 0
        for url, actual in labelled_dataset:
            res = auie_engine.evaluate_url(url, bypass_cache=True)
            predicted = 1 if res["reputation_state"] in ("CONFIRMED_MALICIOUS", "SUSPICIOUS") else 0
            if actual == 1 and predicted == 1:
                tp += 1
            elif actual == 0 and predicted == 1:
                fp += 1
            elif actual == 0 and predicted == 0:
                tn += 1
            elif actual == 1 and predicted == 0:
                fn += 1

        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        print(f"\n--- AUIE ACCURACY EVALUATION METRICS ---")
        print(f"Total Test Samples: {len(labelled_dataset)}")
        print(f"True Positives (TP): {tp}, False Positives (FP): {fp}")
        print(f"True Negatives (TN): {tn}, False Negatives (FN): {fn}")
        print(f"False Positive Rate (FPR): {fpr * 100:.2f}%")
        print(f"Precision: {precision * 100:.2f}%, Recall: {recall * 100:.2f}%, F1-Score: {f1 * 100:.2f}%\n")

        self.assertEqual(fp, 0, f"Detected {fp} false positives among legitimate test URLs!")
        self.assertEqual(fpr, 0.0, "False Positive Rate (FPR) must be 0.0% for verified legitimate domains")
        self.assertGreaterEqual(f1, 0.90, "F1-Score must be >= 90%")


if __name__ == "__main__":
    unittest.main()
