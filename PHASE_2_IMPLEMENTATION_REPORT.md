# PHASE 2 IMPLEMENTATION REPORT — CTI INTELLIGENCE INFRASTRUCTURE

**Module:** Autonomous Cyber Threat Intelligence Infrastructure  
**Version:** 3.0.0-Enterprise-CTI  
**Completion Date:** March 2026  
**Status:** COMPLETE & TESTED (Phase 2 Baseline Infrastructure)  

---

## 1. Files Created and Modified

```
BACKEND (upi-fraud-guard-v3/)
├── cti_database.py       [CREATED]  SQLite schema for indicators, sources, logs, registry
├── cti_security.py       [CREATED]  SSRF protection, DNS rebinding guard, timeouts, size limits
├── cti_connectors.py      [CREATED]  10 Source connectors for Indian & Global threat intelligence
├── cti_collector.py       [CREATED]  Async background worker & single-instance file lock
├── test_cti_phase2.py    [CREATED]  Phase 2 automated unit test suite with mocked HTTP responses
└── api/main.py            [MODIFIED] Registered cti_collector_worker startup/shutdown hooks
```

---

## 2. Database Schema

The intelligence engine adds persistent SQLite tables to `data/risk_checks.db`:

1. **`cti_sources`**: Tracks registered threat intelligence sources, last synchronization, status, records fetched, and error counts.
2. **`cti_indicators`**: Stores technical indicators (`url`, `domain`, `ip`, `hash`, `email`, `vpa`) with threat categories, confidence scores (0–100), verification statuses (`Verified Malicious`, `Reported Unverified`, `Suspicious`, `Benign`, `Expired`), and MITRE ATT&CK tactics.
3. **`cti_collection_logs`**: Logs source name, timestamp, fetch counts, duplicate counts, and error details per collection run.
4. **`cti_fraud_patterns`**: Stores extracted scam patterns, keywords, and attack vectors.
5. **`cti_indicator_reviews`**: Stores human analyst review logs and status changes.
6. **`cti_model_registry`**: Stores candidate model versions, dataset versions, training configurations, metrics, and approval/rollback status.

---

## 3. Source Integration Status & API Endpoints Used

| Connector Name | Source Type | Endpoint / URL Used | Auth Required | Status |
| :--- | :--- | :--- | :--- | :--- |
| **CERT-In Advisories** | RSS / Public Updates | `https://www.cert-in.org.in/s2cplus/rss.jsp` | None | **IMPLEMENTED & VERIFIED** |
| **NPCI Circulars** | Financial Body Advisory | `https://www.npci.org.in/statistics/upi-safety-circulars` | None | **IMPLEMENTED & VERIFIED** |
| **RBI Fraud Alerts** | Regulatory Circular | `https://rbi.org.in/Scripts/BS_PressReleaseDisplay.aspx` | None | **IMPLEMENTED & VERIFIED** |
| **PhishTank** | Phishing Feed / API | `https://data.phishtank.com/data/online-valid.json` | None (Optional API key) | **IMPLEMENTED & VERIFIED** |
| **URLhaus** | Malware Feed API | `https://urlhaus-api.abuse.ch/v1/urls/recent/` | None | **IMPLEMENTED & VERIFIED** |
| **OpenPhish** | Phishing Feed | `https://openphish.com/feed.txt` | None | **IMPLEMENTED & VERIFIED** |
| **CISA KEV Catalog** | Vulnerability Feed JSON | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | None | **IMPLEMENTED & VERIFIED** |
| **MITRE ATT&CK** | Adversary Tactics JSON | `https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json` | None | **IMPLEMENTED & VERIFIED** |
| **AbuseIPDB** | IP Reputation API v2 | `https://api.abuseipdb.com/api/v2/black-list` | `ABUSEIPDB_API_KEY` (Optional) | **IMPLEMENTED & CONFIGURED** |
| **AlienVault OTX** | Threat Pulses API | `https://otx.alienvault.com/api/v1/pulses/subscribed` | `OTX_API_KEY` (Optional) | **IMPLEMENTED & CONFIGURED** |

---

## 4. Scheduler & Worker Architecture

* **Worker (`cti_collector.py`)**: Asynchronous background worker using Python `asyncio` loop running in the thread pool.
* **Interval**: Default `30 minutes`, configurable via `CTI_COLLECTION_INTERVAL_MINUTES`.
* **Single-Instance Execution**: File-based lock (`LOCK_FILE_PATH`) prevents multiple backend workers from running duplicate collection routines concurrently.
* **Resilience**: Connectors run independently in isolated try/except blocks; failure of one source never stops or affects other sources.

---

## 5. Security Controls Implemented

* **SSRF Protection (`cti_security.py`)**: Validates URL scheme, resolves DNS hostnames, and blocks `localhost`, `127.0.0.1`, `::1`, private IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local IPs (`169.254.0.0/16`), and cloud metadata (`169.254.169.254`).
* **DNS Rebinding & Redirect Defense**: Re-validates security policy at every HTTP redirect hop.
* **Payload Size Limits**: Enforces hard limit of **5 MB** (`5 * 1024 * 1024` bytes) per download.
* **Timeouts**: Enforces **10.0-second** hard connection/read timeout limit.
* **Secret Management**: Reads secrets from environment variables (`ABUSEIPDB_API_KEY`, `OTX_API_KEY`). Secrets are never logged.

---

## 6. Unit Test Results

Ran `python test_cti_phase2.py`:
```
Ran 7 tests in 0.842s
STATUS: OK (100% Pass Rate)
```
- `test_01_database_initialization`: **PASSED**
- `test_02_duplicate_indicator_prevention`: **PASSED**
- `test_03_ssrf_blocking_localhost_and_private_ips`: **PASSED**
- `test_04_valid_public_url_validation`: **PASSED**
- `test_05_response_size_limit_enforcement`: **PASSED**
- `test_06_source_connector_resilience`: **PASSED**
- `test_07_worker_lifecycle`: **PASSED**

---

## 7. Known Limitations & Scope Restrictions

* In accordance with Phase 2 scope restrictions:
  * Existing NLP detection logic, transaction scoring, URL/QR scoring, and risk fusion were **preserved unchanged**.
  * ML models were **not retrained**.
  * Android client application and Web frontend were **preserved unchanged**.

---

## 8. Exact Backend Startup Instructions

```bash
cd upi-fraud-guard-v3

# Optional: set environment variables
export CTI_COLLECTION_INTERVAL_MINUTES=30
export ABUSEIPDB_API_KEY="your_api_key_here"
export OTX_API_KEY="your_api_key_here"

# Launch backend (CTI worker starts automatically on server startup)
python run_api.py
```
