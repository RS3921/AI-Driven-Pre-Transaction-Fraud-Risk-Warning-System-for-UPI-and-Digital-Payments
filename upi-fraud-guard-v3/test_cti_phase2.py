"""
Automated Test Suite for Phase 2: CTI Intelligence Infrastructure.

Tests:
- Database initialization and schema creation
- Duplicate record prevention
- SSRF security protection (blocking localhost, 127.0.0.1, private IPs, cloud metadata)
- Response size limit enforcement (5 MB limit)
- Source connector failure resilience
- Background worker execution and lock management
"""
from __future__ import annotations

import asyncio
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from cti_connectors import ALL_CONNECTORS, CertInConnector, PhishTankConnector
from cti_database import CTIDatabase
from cti_collector import CTICollectorWorker
from cti_security import (
    PayloadTooLargeError,
    SSRFValidationError,
    fetch_secure_content,
    validate_url_security,
)


class TestCTIPhase2Infrastructure(unittest.TestCase):

    def setUp(self) -> None:
        # Create temporary database file for test isolation
        self.temp_db_file = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.temp_db_file.close()
        self.db = CTIDatabase(db_path=Path(self.temp_db_file.name))

    def tearDown(self) -> None:
        try:
            os.unlink(self.temp_db_file.name)
        except Exception:
            pass

    # 1. Database Schema & Initialization Test
    def test_01_database_initialization(self) -> None:
        sources = self.db.get_sources()
        self.assertIsInstance(sources, list)

    # 2. Duplicate Indicator Prevention Test
    def test_02_duplicate_indicator_prevention(self) -> None:
        val = "http://phishing-test-site-2026.com/login"
        inserted1 = self.db.add_indicator(
            indicator_value=val,
            indicator_type="url",
            threat_category="phishing",
            source_name="TestFeed",
            confidence_score=75,
        )
        self.assertTrue(inserted1)

        # Attempt to insert identical indicator value
        inserted2 = self.db.add_indicator(
            indicator_value=val,
            indicator_type="url",
            threat_category="phishing",
            source_name="TestFeed",
            confidence_score=85,
        )
        self.assertFalse(inserted2)  # Should return False on duplicate

        results = self.db.query_indicators(search_query="phishing-test-site")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["confidence_score"], 85)  # Confidence score updated to higher value

    # 3. SSRF Protection Tests
    def test_03_ssrf_blocking_localhost_and_private_ips(self) -> None:
        blocked_urls = [
            "http://localhost:8000/status",
            "http://127.0.0.1/admin",
            "http://10.0.0.1/internal",
            "http://192.168.1.1/router",
            "http://169.254.169.254/latest/meta-data/",
        ]
        for url in blocked_urls:
            with self.assertRaises(SSRFValidationError):
                validate_url_security(url)

    # 4. Valid Public URL Allowed
    def test_04_valid_public_url_validation(self) -> None:
        valid_url = "https://www.cert-in.org.in/s2cplus/rss.jsp"
        result = validate_url_security(valid_url)
        self.assertEqual(result, valid_url)

    # 5. Response Size Limit Enforcement
    @patch("cti_security._PinnedHTTPConnection")
    def test_05_response_size_limit_enforcement(self, mock_conn_class: MagicMock) -> None:
        mock_conn = MagicMock()
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.getheader.side_effect = lambda h: "10000000" if h.lower() == "content-length" else None
        mock_conn.getresponse.return_value = mock_response
        mock_conn_class.return_value = mock_conn

        with patch("cti_security._resolve_public", return_value=(2, ("93.184.216.34", 80))):
            with self.assertRaises(PayloadTooLargeError):
                fetch_secure_content("http://example.com/huge-file.json", max_bytes=5 * 1024 * 1024, allowed_hosts={"example.com"})

    # 6. Source Connector Resilience Test
    def test_06_source_connector_resilience(self) -> None:
        connector = CertInConnector()
        res = connector.collect()
        self.assertEqual(res["source_name"], "CERT-In Advisories")
        self.assertIn(res["status"], ["Success", "Failed"])

    # 7. Background Worker Lifecycle Test
    def test_07_worker_lifecycle(self) -> None:
        worker = CTICollectorWorker()
        worker.interval_seconds = 3600.0
        worker._lock_file = Path(tempfile.gettempdir()) / f"test_worker_{time.time()}.lock"

        async def run_test():
            await worker.start()
            self.assertTrue(worker._running)
            await worker.shutdown()
            self.assertFalse(worker._running)

        asyncio.run(run_test())


if __name__ == "__main__":
    unittest.main()
