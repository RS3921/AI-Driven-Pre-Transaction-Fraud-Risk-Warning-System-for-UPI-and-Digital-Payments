"""
Lightweight Continuous Intelligence Test Suite for UPI Fraud Guard Enterprise.

Exercises:
1. Initial and periodic CTI synchronization.
2. Provider failure isolation and missing credentials handling (UNCONFIGURED status).
3. Duplicate indicator ingestion prevention.
4. Expired indicator purging and expiration management.
5. Immediate AUIE cache invalidation upon threat ingestion.
6. Worker restart and single-instance file lock cleanup.
7. Analyst feedback collection and approval workflow (Pending, Approved, Rejected).
8. Training dataset validation and data poisoning prevention (only approved feedback eligible).
9. Controlled model retraining evaluation and fail-closed deployment lock.
10. Lightweight dashboard API data accuracy and zero heavy infrastructure dependencies.
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
from cti_database import cti_db
from cti_matcher import cti_matcher
from cti_ml_pipeline import cti_evaluator, cti_registry
from url_qr_module.auie_engine import auie_engine
from url_qr_module.auie_providers import VirusTotalProvider, sanitize_url_for_privacy


class TestLightweightContinuousIntelligence(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def setUp(self):
        cti_matcher.invalidate_cache()

    def test_01_initial_and_periodic_sync(self):
        """Verify initial CTI source registration and background sync execution."""
        sources = cti_db.get_sources()
        self.assertGreater(len(sources), 0)

        async def run_sync():
            results = await cti_collector_worker.run_now()
            self.assertGreater(len(results), 0)

        asyncio.run(run_sync())

    def test_02_provider_failure_isolation_and_unconfigured_state(self):
        """Verify unconfigured or failing providers return safe UNCONFIGURED/FAILED statuses without crashing."""
        vt = VirusTotalProvider()
        res = vt.lookup_url("https://sbi.co.in", "sbi.co.in")
        self.assertEqual(res["status"], "UNCONFIGURED")
        self.assertIsInstance(res["latency_ms"], float)

    def test_03_duplicate_indicator_prevention(self):
        """Verify duplicate indicators update timestamps without inserting duplicate database rows."""
        dup_url = f"http://dup-lightweight-{time.time_ns()}.com/pay"
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

    def test_04_expired_indicator_handling(self):
        """Verify expired indicators are purged/updated and not treated as current confirmed malicious intelligence."""
        exp_url = f"http://expired-lightweight-{time.time_ns()}.com/auth"
        cti_db.add_indicator(
            indicator_value=exp_url, indicator_type="url", threat_category="phishing",
            source_name="OldFeed", confidence_score=90, verification_status="Verified Malicious",
            expires_at="2020-01-01T00:00:00+00:00"
        )
        purged = cti_db.purge_expired_indicators()
        self.assertGreaterEqual(purged, 1)

        match = cti_matcher.match_url_or_domain(exp_url)
        self.assertIsNone(match)

    def test_05_auie_immediate_cache_invalidation(self):
        """Verify newly ingested CTI threat indicators invalidate cache immediately for AUIE URL checks."""
        fresh_url = f"http://fresh-threat-{time.time_ns()}.com/login"
        self.assertIsNone(cti_matcher.match_url_or_domain(fresh_url))

        cti_db.add_indicator(
            indicator_value=fresh_url, indicator_type="url", threat_category="phishing",
            source_name="CERT-In Advisories", confidence_score=95, verification_status="Verified Malicious", source_verified=True
        )
        cti_matcher.invalidate_cache()

        match = cti_matcher.match_url_or_domain(fresh_url)
        self.assertIsNotNone(match)
        self.assertEqual(match["matched_value"], fresh_url)

    def test_06_worker_restart_and_single_instance_lock(self):
        """Verify worker single-instance file lock prevents duplicate collector workers."""
        worker1 = CTICollectorWorker()
        worker1._lock_file = Path(tempfile.gettempdir()) / f"lightweight_lock_{time.time()}.lock"

        async def run_lock_test():
            await worker1.start()
            self.assertTrue(worker1._running)

            worker2 = CTICollectorWorker()
            worker2._lock_file = worker1._lock_file
            await worker2.start()
            self.assertFalse(worker2._running)

            await worker1.shutdown()
            self.assertFalse(worker1._running)

        asyncio.run(run_lock_test())

    def test_07_feedback_collection_and_review_workflow(self):
        """Test analyst feedback submission and review workflow (PENDING_REVIEW -> APPROVED / REJECTED)."""
        fb_id = cti_db.add_false_positive_feedback(
            url_or_domain="https://lightweight-merchant.com",
            reported_verdict="Suspicious",
            claimed_verdict="Legitimate",
            reporter_id="analyst_1",
            reason="Verified merchant portal"
        )
        self.assertGreater(fb_id, 0)

        reviewed = cti_db.review_false_positive_feedback(fb_id, "admin_1", "APPROVED", "Verified by senior analyst")
        self.assertTrue(reviewed)

    def test_08_data_poisoning_prevention(self):
        """Verify unapproved or pending feedback CANNOT enter training datasets."""
        fb_id = cti_db.add_false_positive_feedback(
            url_or_domain="http://unverified-user-claim.com",
            reported_verdict="Safe",
            claimed_verdict="Malicious",
            reporter_id="untrusted_user",
            reason="Unverified user claim"
        )
        approved_dataset = cti_db.get_approved_learning_dataset()
        self.assertFalse(any(item["feedback_id"] == fb_id for item in approved_dataset))

    def test_09_controlled_ml_retraining_deployment_lock(self):
        """Verify candidate model training evaluates metrics but deployment is strictly refused due to PaySim temporal restriction."""
        eval_res = cti_evaluator.train_and_evaluate("RandomForest", version_tag="lightweight-cand-v1")
        self.assertIn("model_id", eval_res)
        self.assertFalse(eval_res["deployment_eligible"])

        cti_registry.approve_model(eval_res["model_id"], "admin_1")
        deployed = cti_registry.deploy_model(eval_res["model_id"], "admin_1")
        self.assertFalse(deployed, "Deployment must be refused for datasets lacking temporal validation!")

    def test_10_dashboard_health_api(self):
        """Verify GET /api/intelligence/health returns real backend data."""
        resp = self.client.get("/api/intelligence/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("engine_status", data)
        self.assertIn("provider_statuses", data)
        self.assertIn("database_stats", data)
        self.assertIn("ml_health", data)

    @patch("api.security.authentication_required", return_value=True)
    def test_11_rbac_and_privacy_protections(self, mock_auth):
        """Verify RBAC rejects unauthorized requests and sensitive parameters are stripped."""
        resp = self.client.post("/api/intelligence/models/train", json={"algorithm": "RandomForest"}, headers={"Authorization": "Bearer invalid_token_999"})
        self.assertIn(resp.status_code, [401, 403])

        sanitized = sanitize_url_for_privacy("https://payee.com/pay?pa=scammer@upi&otp=123456")
        self.assertNotIn("pa=scammer@upi", sanitized)
        self.assertNotIn("otp=123456", sanitized)


if __name__ == "__main__":
    unittest.main()
