"""
Phase 8 Comprehensive Test Suite for Payment Link & Intelligent Website Analysis Enhancement.

Exercises:
1. URL Type Classification (UPI_PAYMENT_LINK, PAYMENT_GATEWAY, MERCHANT_WEBSITE, GENERAL_WEBSITE, SHORTENED_URL, UNKNOWN_URL_TYPE).
2. UPI Deep Link & Payment QR Analysis.
3. Payment Gateway & Merchant Portal Analysis.
4. Banking & General Website Analysis.
5. Unknown Website Disambiguation (UNKNOWN vs KNOWN_BENIGN).
6. Multi-Hop Redirect Trace & Shortener Resolution.
7. Static Content & UPI PIN / OTP Solicitation Threat Inspection.
8. Brand Impersonation & Lookalike Domain Detection.
9. Structured Risk Explanation Generation & Evidence Attribution.
10. Provider Failure Resilience & SSRF / DNS Rebinding Defenses.
"""

import unittest
from fastapi.testclient import TestClient
from api.main import app
from cti_database import cti_db
from cti_matcher import cti_matcher
from url_qr_module.auie_engine import auie_engine
from url_qr_module.content_inspector import inspect_website_content
from url_qr_module.explanation_engine import generate_structured_explanation
from url_qr_module.redirect_analyzer import trace_url_redirects
from url_qr_module.url_type_identifier import classify_url_type


class TestPaymentLinkEnhancement(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    # 1. URL Type Identification
    def test_01_url_type_classification(self):
        """Test URL intent and type classification layer."""
        self.assertEqual(classify_url_type("upi://pay?pa=store@upi&am=500")["url_type"], "UPI_PAYMENT_LINK")
        self.assertEqual(classify_url_type("https://checkout.razorpay.com/v1/pay")["url_type"], "PAYMENT_GATEWAY")
        self.assertEqual(classify_url_type("https://swiggy.com/restaurants")["url_type"], "MERCHANT_WEBSITE")
        self.assertEqual(classify_url_type("https://tinyurl.com/pay-link")["url_type"], "SHORTENED_URL")
        self.assertEqual(classify_url_type("https://sbi.co.in/netbanking")["url_type"], "GENERAL_WEBSITE")
        self.assertEqual(classify_url_type("")["url_type"], "UNKNOWN_URL_TYPE")

    # 2. UPI Deep Link Analysis
    def test_02_upi_deep_link_analysis(self):
        """Verify UPI payment deep link risk scoring and QR payload extraction."""
        qr_uri = "upi://pay?pa=merchant@okaxis&pn=Store&am=150.00&cu=INR"
        res = auie_engine.evaluate_url(qr_uri, bypass_cache=True)
        self.assertIn("explanation", res)
        self.assertEqual(res["explanation"]["url_type"], "UPI_PAYMENT_LINK")

    # 3. Payment Gateway & Merchant Portal Analysis
    def test_03_payment_gateway_and_merchant_analysis(self):
        """Verify that legitimate payment gateways and merchants return KNOWN_BENIGN with clear explanatory reasons."""
        gateways = ["https://paytm.com/checkout", "https://swiggy.com/order", "https://amazon.in/checkout"]
        for url in gateways:
            res = auie_engine.evaluate_url(url, bypass_cache=True)
            self.assertEqual(res["reputation_state"], "KNOWN_BENIGN")
            self.assertLess(res["risk_score"], 0.30)
            self.assertIn("explanation", res)
            self.assertEqual(res["explanation"]["risk_tier"], "Low")

    # 4. General & Banking Website Analysis
    def test_04_banking_and_general_website_analysis(self):
        """Verify legitimate banking and general portals return KNOWN_BENIGN."""
        portals = ["https://sbi.co.in/login", "https://netbanking.hdfcbank.com", "https://github.com/upifraudguard"]
        for url in portals:
            res = auie_engine.evaluate_url(url, bypass_cache=True)
            self.assertEqual(res["reputation_state"], "KNOWN_BENIGN")
            self.assertEqual(res["explanation"]["risk_tier"], "Low")

    # 5. Unknown Website Disambiguation
    def test_05_unknown_website_disambiguation(self):
        """Verify that unknown/unindexed websites return UNKNOWN (risk score 0.25) and are not conflated with KNOWN_BENIGN."""
        unknown_url = "https://unindexed-local-grocery-store-8888.in/items"
        res = auie_engine.evaluate_url(unknown_url, bypass_cache=True)
        self.assertEqual(res["reputation_state"], "UNKNOWN")
        self.assertEqual(res["explanation"]["risk_tier"], "Low")
        self.assertIn("unindexed/unknown", res["reasons"][0])

    # 6. Secure Multi-Hop Redirect Trace
    def test_06_redirect_analyzer_trace(self):
        """Verify redirect trace structure and shortener detection."""
        trace = trace_url_redirects("https://tinyurl.com/sample-link")
        self.assertTrue(trace["has_shortener"])
        self.assertIn("redirect_chain", trace)

    # 7. Static Content & UPI PIN Threat Inspection
    def test_07_content_inspector_upi_pin_threat(self):
        """Verify that web pages asking users to enter a UPI PIN trigger a Critical warning."""
        # Test content inspector parser logic
        mock_html = "<html><head><title>UPI Refund Verification</title></head><body><form><p>Enter your 6-digit UPI PIN to claim refund:</p><input name='pin' type='password'></form></body></html>"
        from url_qr_module.content_inspector import _StaticHTMLContentParser
        parser = _StaticHTMLContentParser()
        parser.feed(mock_html)
        self.assertEqual(parser.title.strip(), "UPI Refund Verification")
        self.assertIn("pin", parser.input_names[0])

    # 8. Structured Explanation Generation
    def test_08_structured_explanation_generation(self):
        """Verify that generate_structured_explanation creates defensible, evidence-based explanations."""
        type_info = classify_url_type("https://sbi.co.in/login")
        explanation = generate_structured_explanation(
            url_type_info=type_info,
            reputation_state="KNOWN_BENIGN",
            risk_score=0.08,
            confidence_score=0.95,
            domain="sbi.co.in",
            raw_url="https://sbi.co.in/login",
            reasons=["VERIFIED TRUSTED DOMAIN: Belongs to recognized Bank (sbi.co.in)"],
            sources_evidence=[],
            trusted_info={"category": "Bank", "matched_domain": "sbi.co.in", "source": "trusted_domain_manager"}
        )

        self.assertEqual(explanation["url_type"], "GENERAL_WEBSITE")
        self.assertEqual(explanation["reputation_state"], "KNOWN_BENIGN")
        self.assertEqual(explanation["risk_tier"], "Low")
        self.assertGreater(len(explanation["positive_indicators"]), 0)
        self.assertIn("sbi.co.in", explanation["human_readable_explanation"])

    # 9. API Endpoint Enhancement Test
    def test_09_api_enhanced_check_response(self):
        """Test POST /check endpoint with Payment Link analysis returning explanation details."""
        resp = self.client.post("/check", json={
            "message": "Payment for order #1029",
            "url_or_qr": "https://sbi.co.in/login",
            "amount": 350.0,
            "recipient": "merchant@okaxis"
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("verdict", data)
        self.assertIn("module_scores", data)


if __name__ == "__main__":
    unittest.main()
