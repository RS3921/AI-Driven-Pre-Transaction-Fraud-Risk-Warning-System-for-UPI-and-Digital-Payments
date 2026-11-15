# PHASE 3 IMPLEMENTATION REPORT — INTELLIGENCE EXTRACTION, NORMALIZATION & CTI API

**Module:** Autonomous CTI Extraction, Normalization, Verification & CTI REST API  
**Version:** 3.0.0-Enterprise-CTI  
**Completion Date:** March 2026  
**Status:** COMPLETE & TESTED (Phase 3 Extraction, Normalization & API Layer)  

---

## 1. Files Created and Modified

```
BACKEND (upi-fraud-guard-v3/)
├── cti_extraction.py     [CREATED]  Regex & NLP indicator & scam pattern extraction engine
├── cti_normalization.py  [CREATED]  Canonicalization, syntax validation & confidence scoring engine
├── cti_api.py           [CREATED]  Authenticated CTI REST API endpoints with RBAC & pagination
├── test_cti_phase3.py    [CREATED]  Phase 3 integration test suite with synthetic fixtures
├── cti_database.py       [MODIFIED] Refactored table info queries for indicator queries & reviews
└── api/main.py            [MODIFIED] Registered CTI REST API router (/api/intelligence)
```

---

## 2. Extraction Capabilities ([cti_extraction.py](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/cti_extraction.py))

Extracted from unstructured text, XML, JSON, CSV, and HTML advisory feeds without visiting/executing URLs:

* **Technical Indicators**:
  - **URLs**: Scheme, host, path parsing (`URL_PATTERN`)
  - **Domains**: Valid FQDN extraction (`DOMAIN_PATTERN`)
  - **IP Addresses**: IPv4 (`IPV4_PATTERN`) and IPv6 (`IPV6_PATTERN`)
  - **File Hashes**: MD5 (32 hex), SHA-1 (40 hex), SHA-256 (64 hex)
  - **Emails**: Email address syntax matching (`EMAIL_PATTERN`)
  - **VPAs**: Standard UPI handle syntax (`VPA_PATTERN`)
* **Scam Categories & Patterns**:
  - `kyc_fraud`: Fake KYC updates, PAN card block threats, account suspension alerts
  - `otp_harvesting`: Demands to share OTPs, PINs, or verification codes
  - `collect_request_scam`: Fake UPI collect requests and "enter PIN to receive" scams
  - `qr_replacement_scam`: Scan QR to receive cash rewards or claim money
  - `impersonation_scam`: Bank manager, customer care, and helpdesk impersonation
  - `remote_access_scam`: AnyDesk, TeamViewer, RustDesk remote control apps
  - `cashback_reward_scam`: Scratch cards, lottery winnings, reward points
  - `job_investment_scam`: Telegram jobs, part-time work, crypto investment scams

---

## 3. Normalization, Validation & Confidence Methodology ([cti_normalization.py](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/cti_normalization.py))

* **URL Canonicalization**: Lowercases scheme and host, normalizes root path, and strips tracking parameters (`utm_source`, `utm_medium`, `fbclid`, `gclid`, `ref`).
* **Domain Normalization**: Lowercases domain and strips leading `www.` and trailing dots.
* **Syntax Validation**: Enforces IPv4/IPv6 validation via `ipaddress` module, hex length checks for hashes, email regex checks, and `username@handle` syntax for VPAs.
* **Allowlist Protection**: Indicators belonging to trusted domains (`npci.org.in`, `rbi.org.in`, `cert-in.org.in`, `google.com`, `paytm.com`, `sbi.co.in`, etc.) receive `0` confidence and `Allowlisted` status.
* **Evidence-Based Confidence Scoring**:
  - Official Sources (CERT-In, NPCI, RBI, CISA): Base Confidence `90`
  - Curated Threat Feeds (PhishTank, URLhaus, OpenPhish, AbuseIPDB, OTX, MITRE ATT&CK): Base Confidence `75`
  - Unverified General Reports: Base Confidence `45`
  - **Cross-Source Corroboration Boost**: Corroborated indicators reported across 2+ independent sources receive a `+15` boost (capped at `99`).
* **Expiry Rules**:
  - IP indicators: 30 days
  - URL indicators: 60 days
  - Domain/Hash indicators: 90 days

---

## 4. Verification Statuses

1. `Verified Malicious`: Confidence $\ge 85$ OR from official government sources (CERT-In, NPCI, RBI, CISA).
2. `Reported Unverified`: Confidence $50 \text{--} 84$.
3. `Suspicious`: Confidence $30 \text{--} 49$.
4. `Allowlisted`: Listed in trusted domain allowlists.
5. `Expired`: Exceeded indicator retention lifespan.

---

## 5. Authenticated CTI REST API Endpoints ([cti_api.py](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/cti_api.py))

| Endpoint | Method | RBAC Permission | Description |
| :--- | :--- | :--- | :--- |
| `/api/intelligence/status` | `GET` | All Roles | Returns overall CTI engine status, total indicators, and worker state. |
| `/api/intelligence/sources` | `GET` | All Roles | Lists registered CTI sources, last sync times, and fetch stats. |
| `/api/intelligence/indicators` | `GET` | All Roles | Paginated (`limit`, `offset`) indicator search & filter API. |
| `/api/intelligence/indicators/{id}` | `GET` | All Roles | Retrieves detailed evidence payload and review history for an indicator. |
| `/api/intelligence/fraud-patterns` | `GET` | All Roles | Lists recognized scam categories and extracted keywords. |
| `/api/intelligence/collection-logs` | `GET` | All Roles | Paginated (`limit`, `offset`) historical background worker logs. |
| `/api/intelligence/indicators/{id}/review` | `POST` | `super_admin`, `fraud_analyst` | Analyst endpoint to update verification status with audit notes. |

---

## 6. Unit & Integration Test Results

Ran `python test_cti_phase3.py`:
```
Ran 7 tests in 0.177s
STATUS: OK (100% Pass Rate)
```
- `test_01_indicator_extraction`: **PASSED**
- `test_02_canonicalization_and_normalization`: **PASSED**
- `test_03_syntax_validation`: **PASSED**
- `test_04_confidence_and_corroboration`: **PASSED**
- `test_05_allowlist_filtering`: **PASSED**
- `test_06_cti_api_endpoints`: **PASSED**
- `test_07_indicator_manual_review_api`: **PASSED**

---

## 7. Sample Synthetic Records

```json
{
  "indicator_id": "IND-3f8a91b2",
  "indicator_value": "https://fake-upi-verify.com/login?action=verify",
  "indicator_type": "url",
  "threat_category": "phishing",
  "description": "PhishTank Verified Phishing URL",
  "source_name": "PhishTank Feed",
  "confidence_score": 90,
  "verification_status": "Verified Malicious",
  "evidence": ["Extracted URL from PhishTank Feed", "Corroborated across 2 sources"],
  "expires_at": "2026-05-08T08:00:00+00:00"
}
```

---

## 8. Scope Restrictions Checklist

* Existing NLP detection logic, URL scoring, QR parsing, transaction scoring, and `risk_fusion.py` were **preserved unchanged**.
* Existing ML models were **not retrained**.
* Android client and frontend were **preserved unchanged**.
* Phase 4 integration was **not started**.

---

*Phase 3 is completed and verified. In accordance with your instructions, Phase 4 has not been started. Please provide your approval to proceed to Phase 4.*
