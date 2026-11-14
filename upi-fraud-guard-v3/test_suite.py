"""
Enterprise Test Suite for UPI Fraud Guard.

Executes comprehensive integration tests across API endpoints, risk scoring,
0-100 tier actions, dual-feed correlation, NetworkX mule detection, and investigation case management.
"""
from __future__ import annotations

import unittest
from fastapi.testclient import TestClient
from api.main import app


class TestUpiFraudGuardEnterprise(unittest.TestCase):

    def setUp(self) -> None:
        self.client = TestClient(app)

    def test_01_health_and_status(self) -> None:
        response = self.client.get("/status")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "running")
        self.assertEqual(data["version"], "2.6.0-Enterprise")

    def test_02_dual_feed_status(self) -> None:
        response = self.client.get("/feed-status")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["threat_feed"]["healthy"])
        self.assertTrue(data["transaction_feed"]["healthy"])

    def test_03_pre_transaction_check_safe(self) -> None:
        payload = {
            "message": "Payment completed for lunch Rs 250",
            "url_or_qr": "upi://pay?pa=merchant@ybl&pn=Cafe",
            "amount": 250.0,
            "recipient": "merchant@ybl",
        }
        response = self.client.post("/check", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("verdict", data)
        self.assertIn("risk_score", data)
        self.assertIn("risk_score_100", data)
        self.assertIn("recommended_action", data)

    def test_04_pre_transaction_check_threat_vpa(self) -> None:
        payload = {
            "message": "Urgent electricity disconnection. Pay immediately.",
            "url_or_qr": "upi://pay?pa=scammer@upi&pn=Support",
            "amount": 15000.0,
            "recipient": "scammer@upi",
            "payments_last_hour": 6,
            "is_new_recipient": True,
        }
        response = self.client.post("/check", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["verdict"], "High Risk")
        self.assertIn("investigation_case_id", data)
        self.assertIn(data["risk_tier"], ["High", "Critical"])

    def test_05_mule_analysis(self) -> None:
        response = self.client.get("/mule-analysis")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("suspicious_mule_count", data)

    def test_06_investigations_workflow(self) -> None:
        response = self.client.get("/investigations")
        self.assertEqual(response.status_code, 200)
        cases = response.json()
        if cases:
            case_id = cases[0]["case_id"]
            update_payload = {"status": "Under Investigation", "add_note": "Assigned analyst to verify VPA ownership"}
            up_res = self.client.post(f"/investigations/{case_id}/update", json=update_payload)
            self.assertEqual(up_res.status_code, 200)

    def test_07_model_monitoring(self) -> None:
        response = self.client.get("/model-monitoring")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("drift_analysis", data)
        self.assertIn("performance", data)

    def test_08_threat_vpa_addition(self) -> None:
        payload = {"vpa": "new.phishing.scam@upi"}
        response = self.client.post("/threat-intelligence/add-vpa", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["vpa"], "new.phishing.scam@upi")


if __name__ == "__main__":
    unittest.main()
