"""
Automated Integration & Unit Test Suite for Phase 6: Autonomous Intelligence Centre Dashboard Integration.

Tests:
- Frontend static asset endpoints (HTML, JS, CSS)
- CTI Overview Metrics API endpoints
- Threat Indicator Explorer search and filter endpoints
- Manual Collection Trigger endpoint
- Analyst Indicator Review workflow
- Model Registry Dashboard API endpoints (train, approve, deploy, rollback)
- Collection Audit Logs API
"""
from __future__ import annotations

import unittest
from fastapi.testclient import TestClient

from api.main import app
from cti_database import cti_db


class TestCTIPhase6DashboardIntegration(unittest.TestCase):

    def setUp(self) -> None:
        self.client = TestClient(app)

    # 1. Static Frontend Assets Test
    def test_01_static_frontend_assets(self) -> None:
        res_html = self.client.get("/")
        self.assertEqual(res_html.status_code, 200)
        self.assertIn("Autonomous CTI Centre", res_html.text)

        res_js = self.client.get("/script.js")
        self.assertEqual(res_js.status_code, 200)
        self.assertIn("loadCTIDashboard", res_js.text)

    # 2. CTI Overview Status & Sources Test
    def test_02_cti_overview_data(self) -> None:
        res_status = self.client.get("/api/intelligence/status")
        self.assertEqual(res_status.status_code, 200)
        data = res_status.json()
        self.assertIn("total_indicators", data)
        self.assertIn("verified_malicious_count", data)

        res_sources = self.client.get("/api/intelligence/sources")
        self.assertEqual(res_sources.status_code, 200)
        self.assertIsInstance(res_sources.json(), list)

    # 3. Manual Collection Trigger Test
    def test_03_manual_collection_trigger(self) -> None:
        res_collect = self.client.post("/api/intelligence/collect")
        self.assertEqual(res_collect.status_code, 200)
        data = res_collect.json()
        self.assertIn(data["status"], ["Collection Completed", "Completed with failures"])
        self.assertGreater(data["sources_processed"], 0)

    # 4. Threat Indicator Explorer API Test
    def test_04_threat_indicator_explorer(self) -> None:
        # Seed test indicator
        ind_val = "http://phishing-explorer-test-2026.org/login"
        cti_db.add_indicator(
            indicator_value=ind_val,
            indicator_type="url",
            threat_category="phishing",
            source_name="TestFeed",
            confidence_score=85,
            verification_status="Verified Malicious",
        )

        # Search query filter
        res_search = self.client.get("/api/intelligence/indicators?search=phishing-explorer-test")
        self.assertEqual(res_search.status_code, 200)
        data = res_search.json()
        self.assertGreaterEqual(data["total"], 1)

        # Indicator details
        ind_id = data["indicators"][0]["indicator_id"]
        res_det = self.client.get(f"/api/intelligence/indicators/{ind_id}")
        self.assertEqual(res_det.status_code, 200)
        self.assertEqual(res_det.json()["indicator_id"], ind_id)

    # 5. Analyst Review Workflow Test
    def test_05_analyst_review_workflow(self) -> None:
        ind_val = "http://review-workflow-test.com"
        cti_db.add_indicator(
            indicator_value=ind_val,
            indicator_type="url",
            threat_category="phishing",
            source_name="TestFeed",
            confidence_score=60,
            verification_status="Reported Unverified",
        )
        match = cti_db.query_indicators(search_query="review-workflow-test")[0]

        review_res = self.client.post(
            f"/api/intelligence/indicators/{match['indicator_id']}/review",
            json={"new_status": "Allowlisted", "review_notes": "Internal verified domain."},
        )
        self.assertEqual(review_res.status_code, 200)
        self.assertEqual(review_res.json()["new_status"], "Allowlisted")

    # 6. Model Registry Control Panel API Test
    def test_06_model_registry_control_panel(self) -> None:
        # List models
        res_models = self.client.get("/api/intelligence/models")
        self.assertEqual(res_models.status_code, 200)

        # Train candidate
        res_train = self.client.post("/api/intelligence/models/train", json={"algorithm": "RandomForest", "dataset_version": "v1.1.0"})
        self.assertEqual(res_train.status_code, 200)
        candidate_id = res_train.json()["candidate"]["model_id"]

        # Approve candidate
        res_app = self.client.post(f"/api/intelligence/models/{candidate_id}/approve")
        self.assertEqual(res_app.status_code, 200)

        # Candidate uses grouped random holdout only; deployment must remain blocked.
        res_dep = self.client.post(f"/api/intelligence/models/{candidate_id}/deploy")
        self.assertEqual(res_dep.status_code, 422)
        res_roll = self.client.post(f"/api/intelligence/models/{candidate_id}/rollback")
        self.assertEqual(res_roll.status_code, 422)

    # 7. Collection Logs API Test
    def test_07_collection_logs_api(self) -> None:
        res_logs = self.client.get("/api/intelligence/collection-logs?limit=10")
        self.assertEqual(res_logs.status_code, 200)
        self.assertIn("logs", res_logs.json())


if __name__ == "__main__":
    unittest.main()
