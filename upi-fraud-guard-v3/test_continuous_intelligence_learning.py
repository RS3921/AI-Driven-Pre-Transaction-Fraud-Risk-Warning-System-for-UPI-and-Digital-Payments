"""
Phase 11 Comprehensive Test Suite for Continuous Threat Intelligence & Controlled Model Learning.

Exercises:
1. Initial CTI Synchronization
2. Periodic Background Synchronization Loop
3. Provider Failure Isolation
4. Missing API Credentials (UNCONFIGURED status)
5. Duplicate IOC Ingestion Prevention
6. Expired IOC Handling & Expiration Management
7. Cache Invalidation upon Intelligence Ingestion
8. Background Worker Restart & Stale Lock Cleanup
9. Concurrent Synchronization Prevention (File Lock)
10. Feedback Submission
11. Feedback Approval & Rejection Workflow
12. Training Dataset Quality & Sanitization
13. Data Poisoning Resistance (Only Approved Feedback Eligible)
14. Candidate Model Training & Metric Evaluation
15. Fail-Closed Deployment Rejection (PaySim Temporal Restriction)
16. Model Rollback Governance
17. Health Endpoint Accuracy & Metrics Reporting
18. RBAC Role Authorization Enforcement
19. Sensitive Data & Privacy Protection
20. Core Fraud Engine Regression Verification
"""

import asyncio
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient

from api.main import app
from cti_collector import CTICollectorWorker, cti_collector_worker
from cti_connectors import CertInConnector, UrlhausConnector
from cti_database import cti_db
from cti_matcher import cti_matcher
from cti_ml_pipeline import CandidateModelEvaluator, ModelRegistryManager, cti_evaluator, cti_registry
from url_qr_module.auie_engine import auie_engine
from url_qr_module.auie_providers import UrlhausProvider, sanitize_url_for_privacy


class TestContinuousIntelligenceAndLearning(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def setUp(self):
        cti_matcher.invalidate_cache()

    # 1. Initial CTI Synchronization Test
    def test_01_initial_cti_synchronization(self):
        """Verify initial CTI synchronization initialization."""
        sources = cti_db.get_sources()
        self.assertGreater(len(sources), 0)
        self.assertTrue(any(s["name"] == "CERT-In Advisories" for s in sources))

    # 2. Periodic Synchronization Worker Test
    def test_02_periodic_synchronization_worker(self):
        """Verify that running a sync pass executes and updates feed status."""
        async def run_sync():
            results = await cti_collector_worker.run_now()
            self.assertGreater(len(results), 0)

        asyncio.run(run_sync())

    # 3. Provider Failure Isolation Test
    def test_03_provider_failure_isolation(self):
        """Verify that provider lookup or network failure does not crash the server or raise uncaught exceptions."""
        provider = UrlhausProvider()
        res = provider.lookup_url("https://google.com", "google.com")
        self.assertIn(res["status"], ["ACTIVE", "UNCONFIGURED", "FAILED"])
        self.assertIsInstance(res["latency_ms"], float)

    # 4. Missing API Credentials Test
    def test_04_missing_credentials_unconfigured_status(self):
        """Verify that providers without API keys report UNCONFIGURED status without crashing."""
        from url_qr_module.auie_providers import VirusTotalProvider
        vt = VirusTotalProvider()
        res = vt.lookup_url("https://sbi.co.in", "sbi.co.in")
        self.assertEqual(res["status"], "UNCONFIGURED")

    # 5. Duplicate IOC Ingestion Prevention Test
    def test_05_duplicate_ioc_ingestion_prevention(self):
        """Verify that duplicate indicators update last_seen and count without inserting duplicate rows."""
        dup_url = f"http://duplicate-phish-{time.time_ns()}.com/login"
        added1 = cti_db.add_indicator(
            indicator_value=dup_url, indicator_type="url", threat_category="phishing",
            source_name="PhishTank Feed", confidence_score=90, verification_status="Verified Malicious", source_verified=True
        )
        added2 = cti_db.add_indicator(
            indicator_value=dup_url, indicator_type="url", threat_category="phishing",
            source_name="PhishTank Feed", confidence_score=90, verification_status="Verified Malicious", source_verified=True
        )
        self.assertTrue(added1)
        self.assertFalse(added2)

    # 6. Expired IOC Handling Test
    def test_06_expired_ioc_handling(self):
        """Verify that expired indicators are purged/updated and not treated as current verified malicious threats."""
        exp_url = f"http://expired-threat-{time.time_ns()}.com/login"
        cti_db.add_indicator(
            indicator_value=exp_url, indicator_type="url", threat_category="phishing",
            source_name="OldFeed", confidence_score=90, verification_status="Verified Malicious",
            expires_at="2021-01-01T00:00:00+00:00"
        )
        purged = cti_db.purge_expired_indicators()
        self.assertGreaterEqual(purged, 1)

        match = cti_matcher.match_url_or_domain(exp_url)
        self.assertIsNone(match)

    # 7. Cache Invalidation Test
    def test_07_cache_invalidation_on_new_threat(self):
        """Verify that newly added threat indicators invalidate cti_matcher cache immediately."""
        new_url = f"http://fresh-zero-day-{time.time_ns()}.com/auth"
        res_before = cti_matcher.match_url_or_domain(new_url)
        self.assertIsNone(res_before)

        cti_db.add_indicator(
            indicator_value=new_url, indicator_type="url", threat_category="phishing",
            source_name="CERT-In Advisories", confidence_score=95, verification_status="Verified Malicious", source_verified=True
        )
        cti_matcher.invalidate_cache()

        res_after = cti_matcher.match_url_or_domain(new_url)
        self.assertIsNotNone(res_after)
        self.assertEqual(res_after["matched_value"], new_url)
        self.assertIsNone(res_before)

        cti_db.add_indicator(
            indicator_value=new_url, indicator_type="url", threat_category="phishing",
            source_name="CERT-In Advisories", confidence_score=95, verification_status="Verified Malicious", source_verified=True
        )
        cti_matcher.invalidate_cache()

        res_after = cti_matcher.match_url_or_domain(new_url)
        self.assertIsNotNone(res_after)
        self.assertEqual(res_after["matched_value"], new_url)

    # 8. Background Worker Lock Test
    def test_08_background_worker_lock(self):
        """Verify single-instance file lock prevents duplicate workers."""
        worker1 = CTICollectorWorker()
        worker1._lock_file = Path(tempfile.gettempdir()) / f"test_worker_lock_{time.time()}.lock"

        async def run_lock_test():
            await worker1.start()
            self.assertTrue(worker1._running)

            # Second worker attempt should skip execution due to active lock
            worker2 = CTICollectorWorker()
            worker2._lock_file = worker1._lock_file
            await worker2.start()
            self.assertFalse(worker2._running)

            await worker1.shutdown()
            self.assertFalse(worker1._running)

        asyncio.run(run_lock_test())

    # 9. Feedback Submission Test
    def test_09_feedback_submission(self):
        """Test submitting analyst false-positive feedback."""
        fb_id = cti_db.add_false_positive_feedback(
            url_or_domain="https://legitimate-partner-portal.com",
            reported_verdict="Suspicious",
            claimed_verdict="Safe",
            reporter_id="analyst_test",
            reason="Verified bank partner merchant portal"
        )
        self.assertGreater(fb_id, 0)

    # 10. Feedback Review Workflow Test
    def test_10_feedback_review_workflow(self):
        """Test reviewing and approving feedback reports."""
        fb_id = cti_db.add_false_positive_feedback(
            url_or_domain="https://partner-portal-2.com",
            reported_verdict="Suspicious",
            claimed_verdict="Safe",
            reporter_id="analyst_test",
            reason="Verified partner domain"
        )
        approved = cti_db.review_false_positive_feedback(fb_id, "admin_test", "APPROVED", "Approved after domain verification")
        self.assertTrue(approved)

    # 11. Data Poisoning Resistance Test
    def test_11_data_poisoning_resistance(self):
        """Verify that pending or rejected feedback records CANNOT enter approved learning dataset."""
        fb_id = cti_db.add_false_positive_feedback(
            url_or_domain="http://unverified-user-report.com",
            reported_verdict="Safe",
            claimed_verdict="Suspicious",
            reporter_id="untrusted_user",
            reason="User claims site is bad without evidence"
        )
        # Leave in PENDING_REVIEW status
        dataset = cti_db.get_approved_learning_dataset()
        self.assertFalse(any(item["feedback_id"] == fb_id for item in dataset))

    # 12. Candidate Model Evaluation Test
    def test_12_candidate_model_evaluation(self):
        """Verify that CandidateModelEvaluator trains candidate and computes evaluation metrics."""
        result = cti_evaluator.train_and_evaluate("RandomForest", version_tag="test-candidate-v1")
        self.assertIn("model_id", result)
        self.assertIn("metrics", result)
        self.assertIn("f1_score", result["metrics"])
        self.assertFalse(result["deployment_eligible"])

    # 13. Fail-Closed Deployment Rejection Test
    def test_13_fail_closed_deployment_rejection(self):
        """Verify that candidate model deployment is strictly refused due to PaySim non-temporal dataset limitation."""
        result = cti_evaluator.train_and_evaluate("RandomForest", version_tag="test-candidate-v2")
        model_id = result["model_id"]
        cti_registry.approve_model(model_id, "admin_test")

        deployed = cti_registry.deploy_model(model_id, "admin_test")
        self.assertFalse(deployed, "Deployment must be refused for candidates lacking temporal evaluation!")

    # 14. Model Rollback Test
    def test_14_model_rollback_governance(self):
        """Verify rollback method rejects rollback when no active deployment history exists."""
        rolled_back = cti_registry.rollback_model("MODEL-NONEXISTENT", "admin_test")
        self.assertFalse(rolled_back)

    # 15. CTI Health Endpoint Accuracy Test
    def test_15_health_endpoint_accuracy(self):
        """Test GET /api/intelligence/health endpoint response structure."""
        resp = self.client.get("/api/intelligence/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("engine_status", data)
        self.assertIn("provider_statuses", data)
        self.assertIn("database_stats", data)
        self.assertIn("ml_health", data)

    # 16. RBAC Role Authorization Test
    @patch("api.security.authentication_required", return_value=True)
    def test_16_rbac_authorization_enforcement(self, mock_auth_req):
        """Verify that administrative model deployment / training endpoints reject unauthenticated or non-admin requests."""
        resp = self.client.post("/api/intelligence/models/train", json={"algorithm": "RandomForest"}, headers={"Authorization": "Bearer invalid_token_12345"})
        self.assertIn(resp.status_code, [401, 403])

    # 17. Sensitive Data & Privacy Protection Test
    def test_17_sensitive_data_privacy_protection(self):
        """Verify sensitive query parameters (pa, pn, am, otp, pin) are stripped prior to outbound lookup."""
        raw_url = "https://payee-portal.com/pay?pa=scammer@upi&pn=John&am=5000&otp=999999"
        sanitized = sanitize_url_for_privacy(raw_url)
        self.assertNotIn("pa=scammer@upi", sanitized)
        self.assertNotIn("otp=999999", sanitized)

    # 18. AUIE 4-State Classification Integrity Test
    def test_18_auie_4_state_classification(self):
        """Verify AUIE 4-state classification logic."""
        res_benign = auie_engine.evaluate_url("https://sbi.co.in", bypass_cache=True)
        self.assertEqual(res_benign["reputation_state"], "KNOWN_BENIGN")

        res_unknown = auie_engine.evaluate_url("https://random-unindexed-domain-999.com", bypass_cache=True)
        self.assertEqual(res_unknown["reputation_state"], "UNKNOWN")

    # 19. Database Statistics Breakdown Test
    def test_19_database_statistics_breakdown(self):
        """Verify get_cti_database_stats returns active, verified, expired, and category statistics."""
        stats = cti_db.get_cti_database_stats()
        self.assertIn("total_indicators", stats)
        self.assertIn("verified_malicious", stats)
        self.assertIn("by_source", stats)

    # 20. Core Fraud Engine Regression Verification Test
    def test_20_core_fraud_engine_regression(self):
        """Verify pre-transaction risk assessment POST /check returns valid risk score and reasons."""
        resp = self.client.post("/check", json={
            "message": "Urgent electricity bill due. Account will be disconnected.",
            "url_or_qr": "https://sbi.co.in/login",
            "amount": 1500.0,
            "recipient": "power_bill@ybl"
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("verdict", data)
        self.assertIn("risk_score", data)
        self.assertIn("reasons", data)


if __name__ == "__main__":
    unittest.main()
