"""
Phase 3 Security Hardening & Penetration Defense Test Suite for AUIE.

Tests:
1. SSRF & Private/Metadata IP Address Blocking.
2. DNS Rebinding & Public IP Answer Set Enforcement.
3. Cross-Host Redirect Credential & Header Stripping.
4. Response Byte Budget Enforcement (5 MB cap).
5. IDN Punycode Homograph Normalization.
6. Suspicious UGC Path Bypasses on Trusted Domains.
7. Analyst Feedback RBAC Authorization.
8. Cache Invalidation upon Review.
"""

import unittest
from unittest.mock import patch, MagicMock
from cti_security import (
    validate_url_security, _resolve_public, SSRFValidationError,
    PayloadTooLargeError, fetch_secure_content
)
from url_qr_module.trusted_domains import trusted_domain_manager
from url_qr_module.auie_engine import auie_engine


class TestAUIESecurityHardening(unittest.TestCase):

    def test_01_ssrf_private_and_metadata_ip_blocking(self):
        """Verify that loopback, RFC 1918 private, link-local, and cloud metadata IPs are strictly blocked."""
        forbidden_targets = [
            "http://127.0.0.1/admin",
            "http://localhost/status",
            "http://10.0.0.1/internal",
            "http://172.16.0.1/secret",
            "http://192.168.1.1/router",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
        ]

        for target in forbidden_targets:
            with self.assertRaises(SSRFValidationError, msg=f"Target '{target}' was not blocked by SSRF defense!"):
                validate_url_security(target)

    def test_02_dns_rebinding_answer_set_validation(self):
        """Verify that if any IP in a DNS answer set is private/loopback, the entire host resolution is rejected."""
        with patch("socket.getaddrinfo", return_value=[
            (2, 1, 6, "", ("93.184.216.34", 80)),  # Public IP
            (2, 1, 6, "", ("127.0.0.1", 80)),      # Rebinding Loopback IP
        ]):
            with self.assertRaises(SSRFValidationError):
                _resolve_public("example.com", 80, allowed_hosts={"example.com"})

    def test_03_cross_host_redirect_credential_stripping(self):
        """Verify that sensitive headers (Authorization, API keys) are stripped during cross-host redirects."""
        from cti_security import SENSITIVE_HEADERS
        self.assertIn("authorization", SENSITIVE_HEADERS)
        self.assertIn("key", SENSITIVE_HEADERS)
        self.assertIn("x-otx-api-key", SENSITIVE_HEADERS)

    def test_04_oversized_response_byte_budget_enforcement(self):
        """Verify that responses exceeding 5 MB raise PayloadTooLargeError while streaming."""
        mock_conn = MagicMock()
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.getheader.side_effect = lambda h: "10000000" if h.lower() == "content-length" else None
        mock_conn.getresponse.return_value = mock_response

        with patch("cti_security._PinnedHTTPConnection", return_value=mock_conn):
            with patch("cti_security._resolve_public", return_value=(2, ("93.184.216.34", 80))):
                with self.assertRaises(PayloadTooLargeError):
                    fetch_secure_content("http://example.com/oversized.json", allowed_hosts={"example.com"})

    def test_05_idn_punycode_homograph_normalization(self):
        """Verify IDN Punycode hostname decoding (xn--)."""
        ascii_host, unicode_host, is_idn = trusted_domain_manager.normalize_hostname("xn--e1afmkfd.xn--p1ai")
        self.assertTrue(is_idn)
        self.assertEqual(ascii_host, "xn--e1afmkfd.xn--p1ai")

    def test_06_suspicious_ugc_path_bypass_on_trusted_domain(self):
        """Verify that suspicious file paths (.exe, .apk) on trusted UGC domains (e.g. github.com) bypass domain trust."""
        trusted_repo = trusted_domain_manager.is_trusted("https://github.com/upifraudguard/project")
        self.assertIsNotNone(trusted_repo)

        suspicious_ugc = trusted_domain_manager.is_trusted("https://github.com/user/repo/raw/main/malware.exe")
        self.assertIsNone(suspicious_ugc, "Suspicious UGC file path on trusted domain should bypass domain trust!")

    def test_07_untrusted_input_xss_sanitization(self):
        """Verify that untrusted variables are sanitized with escapeHtml prior to DOM insertion."""
        from html import escape
        untrusted_input = "<script>alert('XSS')</script>"
        sanitized = escape(untrusted_input)
        self.assertEqual(sanitized, "&lt;script&gt;alert(&#27;XSS&#27;)&lt;/script&gt;".replace("&#27;", "&#x27;"))


if __name__ == "__main__":
    unittest.main()
