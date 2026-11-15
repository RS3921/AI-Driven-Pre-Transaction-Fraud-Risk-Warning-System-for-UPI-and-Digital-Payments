# PAYMENT LINK INTELLIGENCE ENHANCEMENT REPORT
**UPI Fraud Guard Enterprise v2.6.0-RC1**

**Date:** 2026-11-10  
**Target Platform:** `upi-fraud-guard-v3` Backend & Dashboard  
**Status:** FULLY IMPLEMENTED & VERIFIED (75/75 Tests Passed Across All 11 Test Suites)

---

## 1. Executive Summary & Previous Limitations

The **Adaptive URL Intelligence Engine (AUIE)** has been enhanced to support intelligent, evidence-based analysis for both payment-related URLs (`upi://pay`, hosted payment gateway checkout flows) and ordinary website URLs.

### Previous Limitations Addressed
1. **Keyword Over-Penalization:** Legacy lexical filters penalized words like `login`, `bank`, `account`, `pay`, and `secure` indiscriminately. The enhanced engine checks domain reputation first, preventing legitimate banking and payment portals from being flagged.
2. **Lack of URL Type Intent Classification:** Previous checks treated all URLs identically. The enhanced engine introduces an explicit URL intent layer (`UPI_PAYMENT_LINK`, `PAYMENT_GATEWAY`, `MERCHANT_WEBSITE`, `GENERAL_WEBSITE`, `SHORTENED_URL`, `UNKNOWN_URL_TYPE`).
3. **Missing Static Content & Form Inspection:** AUIE now performs safe, isolated HTML parsing to detect credential collection forms, brand impersonation cues, and **UPI PIN solicitation threats**.
4. **Unverified Multi-Hop Redirects:** Added a secure multi-hop redirect trace engine that resolves shortened links (`bit.ly`, `tinyurl.com`) while validating SSRF security on every hop.

---

## 2. Enhanced System Architecture

```
                        [ User / Application Input URL ]
                                       │
                                       ▼
                   ┌───────────────────────────────────────┐
                   │ Phase 1: URL Type & Intent Identifier │
                   └───────────────────┬───────────────────┘
                                       │
                                       ▼
                   ┌───────────────────────────────────────┐
                   │  Phase 3: Secure Multi-Hop Redirect   │
                   │  Trace & Shortener Expander           │
                   └───────────────────┬───────────────────┘
                                       │
                                       ▼
                   ┌───────────────────────────────────────┐
                   │ Phase 2: Static Content & Form        │
                   │ Inspector (UPI PIN Threat Detection)  │
                   └───────────────────┬───────────────────┘
                                       │
                                       ▼
                   ┌───────────────────────────────────────┐
                   │ Phase 4: AUIE 4-State Risk Fusion &   │
                   │ CTI Threat Intelligence Matching      │
                   └───────────────────┬───────────────────┘
                                       │
                                       ▼
                   ┌───────────────────────────────────────┐
                   │ Phase 5: Structured Risk Explanation  │
                   │ & Human Advisory Generation           │
                   └───────────────────┬───────────────────┘
                                       │
                                       ▼
             [ Dashboard UI Output & REST API Return Payload ]
```

---

## 3. URL Type & Intent Classifications

The URL Type Identifier ([`url_qr_module/url_type_identifier.py`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/url_qr_module/url_type_identifier.py)) categorizes inputs into:

- `UPI_PAYMENT_LINK`: UPI deep links (`upi://pay?...`) and QR payloads.
- `PAYMENT_GATEWAY`: Hosted checkout gateways (`checkout.razorpay.com`, `paytm.com/checkout`, `payu.in`, `billdesk.com`, `cashfree.com`, `stripe.com`).
- `MERCHANT_WEBSITE`: Verified e-commerce and merchant portals (`swiggy.com`, `zomato.com`, `amazon.in`, `flipkart.com`, `myntra.com`, `meesho.com`).
- `GENERAL_WEBSITE`: General HTTP/HTTPS portals (`sbi.co.in`, `gov.in`, `github.com`, `wikipedia.org`).
- `SHORTENED_URL`: Link shorteners (`bit.ly`, `tinyurl.com`, `t.co`, `cutt.ly`, `rb.gy`).
- `UNKNOWN_URL_TYPE`: Unparseable or malformed inputs.

---

## 4. Intelligent Website & Content Analysis

The Static Content Inspector ([`url_qr_module/content_inspector.py`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/url_qr_module/content_inspector.py)) performs safe, isolated HTML parsing (up to 512 KiB) without executing JavaScript or binary downloads:

### Critical Warning Indicator: UPI PIN Solicitation
If a web page or HTML form requests the user's UPI PIN / MPIN, AUIE triggers a **Critical Warning**:

> [!CAUTION]
> **CRITICAL SECURITY THREAT:** Website or web form solicits entry of a UPI PIN or MPIN.  
> *Why it matters:* You should **NEVER** enter your UPI PIN on any website or browser form. UPI PIN is strictly entered **ONLY** inside your official UPI mobile payment app (Google Pay, PhonePe, Paytm, BHIM) when authorizing a payment transfer.

---

## 5. Secure Multi-Hop Redirect Trace

The Redirect Analyzer ([`url_qr_module/redirect_analyzer.py`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/url_qr_module/redirect_analyzer.py)) traces HTTP/HTTPS redirects hop-by-hop up to 5 hops:
- **SSRF Validation:** Every redirect destination host is resolved and validated upfront via `_resolve_public()`. Private/loopback/cloud metadata IPs (`127.0.0.1`, `10.0.0.1`, `169.254.169.254`) raise `SSRFValidationError`.
- **Cross-Host Credential Stripping:** Sensitive headers (`Authorization`, `cookie`, `key`, `x-otx-api-key`) are automatically stripped when crossing domain boundaries.
- **Redirect Loops & Hop Limits:** Detects redirect loops and per-hop timeouts (1.5s cap per hop).

---

## 6. Structured Risk Explanation Engine

The Explanation Engine ([`url_qr_module/explanation_engine.py`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/url_qr_module/explanation_engine.py)) generates structured explanations for every request:

```json
{
  "url_type": "GENERAL_WEBSITE",
  "category_description": "General Website / Portal",
  "reputation_state": "KNOWN_BENIGN",
  "risk_score": 0.08,
  "confidence_score": 0.95,
  "risk_tier": "Low",
  "recommended_action": "LOW RISK: Proceed with normal payment precautions.",
  "human_readable_explanation": "The submitted URL belongs to the verified official portal for 'sbi.co.in' (Bank). No known malicious threat indicators were found.",
  "positive_indicators": [
    {
      "name": "Verified Domain Allowlist (Bank)",
      "finding": "Domain 'sbi.co.in' is a recognized legitimate portal in official registries.",
      "why_it_matters": "Official verified banking, payment gateway, and government domains carry a low baseline probability of malicious intent.",
      "source": "trusted_domain_manager",
      "type": "confirmed",
      "contribution": "decreased_risk"
    }
  ],
  "negative_indicators": [],
  "threat_intel_matches": [],
  "unavailable_checks": []
}
```

---

## 7. Exact Files Created and Modified

### New Source Modules Created
- [`upi-fraud-guard-v3/url_qr_module/url_type_identifier.py`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/url_qr_module/url_type_identifier.py): URL intent & type classification layer.
- [`upi-fraud-guard-v3/url_qr_module/redirect_analyzer.py`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/url_qr_module/redirect_analyzer.py): Secure multi-hop redirect trace & shortener resolution.
- [`upi-fraud-guard-v3/url_qr_module/content_inspector.py`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/url_qr_module/content_inspector.py): Static HTML content parser & UPI PIN threat detector.
- [`upi-fraud-guard-v3/url_qr_module/explanation_engine.py`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/url_qr_module/explanation_engine.py): Structured explanation & human-readable advisory generator.
- [`upi-fraud-guard-v3/test_payment_link_enhancement.py`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/test_payment_link_enhancement.py): Phase 8 test suite for payment link and website analysis enhancement.

### Modified Source Files
- [`upi-fraud-guard-v3/url_qr_module/auie_engine.py`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/url_qr_module/auie_engine.py): Integrated URL type classification, redirect trace, content inspection, and structured explanation generation.
- [`upi-fraud-guard-v3/frontend/index.html`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/frontend/index.html): Added URL type badge, advisory box, positive/negative indicator lists, and expandable technical evidence trace.
- [`upi-fraud-guard-v3/frontend/script.js`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/frontend/script.js): Enhanced AUIE UI handler with structured explanation formatting and XSS sanitization (`escapeHtml()`).

---

## 8. Test Execution Summary

```text
Ran 75 tests in 425.092s — OK
```

- **Total Test Modules:** 11 (`test_payment_link_enhancement.py`, `test_auie_security_hardening.py`, `test_auie_expanded_benchmark.py`, `test_auie.py`, `test_critical_remediations.py`, `test_cti_phase2.py`, `test_cti_phase3.py`, `test_cti_phase4.py`, `test_cti_phase5.py`, `test_cti_phase6.py`, `test_suite.py`)
- **Total Tests Passed:** 75 / 75 (100%)
- **Failing Tests:** 0

---

## 9. Deployment & Pilot Recommendations

### **Classification:** **READY FOR CONTROLLED PILOT WITH DOCUMENTED RESTRICTIONS**

> [!IMPORTANT]
> **Deployment Recommendations:**
> 1. **Commercial CTI API Keys:** Supply `GOOGLE_WEB_RISK_API_KEY`, `VIRUSTOTAL_API_KEY`, `URLHAUS_API_KEY`, and `OTX_API_KEY` in `.env` for commercial live lookups.
> 2. **Physical Device QR Scanning:** Verify camera barcode decoding on physical Android hardware during pilot.
> 3. **Production TLS Binding:** Mount valid PEM-encoded TLS certs (`UPI_FRAUD_GUARD_TLS_CERT`, `UPI_FRAUD_GUARD_TLS_KEY`) when binding server to non-loopback network interfaces.
