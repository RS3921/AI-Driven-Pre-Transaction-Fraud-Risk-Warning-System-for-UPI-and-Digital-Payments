"""Regression coverage for CTI integrity and secure source fetching."""
from __future__ import annotations

import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import cti_connectors
import cti_security
from cti_connectors import BaseSourceConnector, SourceUnconfigured, _document_indicators
from cti_database import CTIDatabase
from cti_security import PayloadTooLargeError, SSRFValidationError, fetch_secure_content


class _HTTPHandler(BaseHTTPRequestHandler):
    received_secret = None
    def do_GET(self):
        if self.path == "/start":
            self.send_response(302)
            self.send_header("Location", f"http://redirect.test:{self.server.server_port}/target")
            self.end_headers()
        elif self.path == "/target":
            type(self).received_secret = self.headers.get("Key")
            payload = b"ok"
            self.send_response(200); self.send_header("Content-Length", str(len(payload))); self.end_headers()
            self.wfile.write(payload)
        elif self.path == "/large":
            self.send_response(200); self.send_header("Transfer-Encoding", "chunked"); self.end_headers()
            self.wfile.write(b"4\r\nABCD\r\n4\r\nEFGH\r\n0\r\n\r\n")
        else:
            payload = b"ok"
            self.send_response(200); self.send_header("Content-Length", str(len(payload))); self.end_headers()
            self.wfile.write(payload)
    def log_message(self, *_args):
        pass

class TestCriticalRemediations(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.db = CTIDatabase(Path(self.temp.name) / "test.db")
        self.db_patch = patch.object(cti_connectors, "cti_db", self.db)
        self.db_patch.start()

    def tearDown(self):
        self.db_patch.stop()
        self.temp.cleanup()

    def test_failed_source_does_not_insert_fallback(self):
        class Broken(BaseSourceConnector):
            def fetch_records(self):
                raise RuntimeError("upstream unavailable")
        connector = Broken("TEST", "Test failing source", "test", "https://example.test")
        result = connector.collect()
        self.assertEqual(result["status"], "Failed")
        self.assertEqual(result["inserted_indicators"], 0)
        self.assertEqual(self.db.query_indicators(limit=10), [])
        self.assertEqual(self.db.get_sources()[0]["status"], "Failed")

    def test_missing_credentials_are_unconfigured(self):
        class CredentialSource(BaseSourceConnector):
            def fetch_records(self):
                self.fail("fetch must not run without a key")
        connector = CredentialSource("TESTKEY", "Keyed source", "test", "https://example.test", "MISSING_TEST_KEY")
        with patch.dict("os.environ", {}, clear=True):
            result = connector.collect()
        self.assertEqual(result["status"], "Unconfigured")
        self.assertEqual(self.db.query_indicators(limit=10), [])

    def test_retrieved_advisory_content_is_extracted_and_stored_unverified(self):
        class Advisory(BaseSourceConnector):
            def fetch_records(self):
                return _document_indicators(
                    "Phishing report: http://credential-theft.example/login",
                    self.name, self.url, "advisory_reference")
        connector = Advisory("ADVISORY", "Test advisory", "test", "https://example.test/feed")
        result = connector.collect()
        self.assertEqual(result["status"], "Success")
        self.assertEqual(result["inserted_indicators"], 1)
        item = self.db.query_indicators(search_query="credential-theft.example", limit=10)[0]
        self.assertEqual(item["indicator_type"], "url")
        self.assertEqual(item["verification_status"], "Reported Unverified")
        self.assertEqual(item["source_count"], 1)
        self.assertTrue(item["evidence"])

    def test_confidence_alone_does_not_verify(self):
        from cti_normalization import intelligence_normalizer
        _, status, _ = intelligence_normalizer.calculate_confidence_and_status(
            "http://suspect.example", "url", "untrusted", base_confidence=99)
        self.assertEqual(status, "Reported Unverified")

    def test_private_ipv4_ipv6_localhost_and_metadata_are_rejected(self):
        for url in ("http://127.0.0.1/", "http://10.0.0.1/", "http://[::1]/",
                    "http://[fe80::1]/", "http://169.254.169.254/"):
            with self.subTest(url=url), self.assertRaises(SSRFValidationError):
                cti_security.validate_url_security(url, allowed_hosts=set())

    def _server(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), _HTTPHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def cleanup():
            try:
                server.shutdown()
            except Exception:
                pass
            try:
                server.server_close()
            except Exception:
                pass
            thread.join(timeout=1.0)
        self.addCleanup(cleanup)
        return server

    def _fake_resolver(self, host, port, allowed_hosts=None):
        if host not in {"source.test", "redirect.test"}:
            raise SSRFValidationError("not allowed")
        return 2, ("127.0.0.1", port)

    def test_cross_host_redirect_does_not_forward_credentials(self):
        server = self._server()
        _HTTPHandler.received_secret = None
        with patch.object(cti_security, "_resolve_public", side_effect=self._fake_resolver):
            data = fetch_secure_content(f"http://source.test:{server.server_port}/start",
                headers={"Key":"secret"}, allowed_hosts={"source.test","redirect.test"})
        self.assertEqual(data, b"ok")
        self.assertIsNone(_HTTPHandler.received_secret)

    def test_streaming_limit_rejects_chunked_oversize_body(self):
        server = self._server()
        with patch.object(cti_security, "_resolve_public", side_effect=self._fake_resolver):
            with self.assertRaises(PayloadTooLargeError):
                fetch_secure_content(f"http://source.test:{server.server_port}/large",
                    max_bytes=5, allowed_hosts={"source.test"})

    def test_pinned_fetch_uses_resolved_ip(self):
        server = self._server()
        real_create = cti_security.socket.create_connection
        destinations = []
        def capture(address, *args, **kwargs):
            destinations.append(address)
            return real_create(address, *args, **kwargs)
        with patch.object(cti_security, "_resolve_public", side_effect=self._fake_resolver), \
             patch.object(cti_security.socket, "create_connection", side_effect=capture):
            self.assertEqual(fetch_secure_content(f"http://source.test:{server.server_port}/ok",
                allowed_hosts={"source.test"}), b"ok")
        self.assertEqual(destinations[0][0], "127.0.0.1")

if __name__ == "__main__":
    unittest.main()
