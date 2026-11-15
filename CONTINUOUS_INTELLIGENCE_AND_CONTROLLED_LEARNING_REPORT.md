# CONTINUOUS THREAT INTELLIGENCE & CONTROLLED MODEL LEARNING REPORT
**UPI Fraud Guard Enterprise v2.6.0-RC1**

**Date:** 2026-11-10  
**Target Release Version:** `v2.6.0-RC1` (`2.6.0-Enterprise`)  
**Workspace Root:** `C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved`  
**Backend Subproject:** `upi-fraud-guard-v3`  
**Status:** FULLY IMPLEMENTED, AUDITED & VERIFIED (20/20 New Tests + All Regression Suites Passed)

---

## 1. Executive Summary & Original Architecture Discovered

An end-to-end implementation and technical audit of the **Continuous Threat Intelligence (CTI) & Controlled Model Learning System** was conducted for **UPI Fraud Guard Enterprise v2.6.0-RC1**. 

### System Audit Findings (Phase 1)
- **Automatic CTI Synchronization:** `CTICollectorWorker` executes scheduled background thread passes across 10 Indian and global threat feeds (CERT-In, NPCI, RBI, PhishTank, URLhaus, OpenPhish, CISA KEV, MITRE ATT&CK, AbuseIPDB, AlienVault OTX) with a single-instance file lock (`cti_collector.lock`) and configurable sleep intervals (`CTI_COLLECTION_INTERVAL_MINUTES`).
- **Real-Time AUIE Integration:** Newly ingested verified indicators automatically purge `cti_matcher`'s in-memory cache, enabling AUIE URL checks to immediately match newly identified threats without requiring server restarts or model retraining.
- **Controlled ML Deployment Lock:** Candidate models trained on `transactions_dataset.csv` strictly fail closed upon deployment attempts (`Refusing model deployment: candidate lacks eligible temporal evaluation`) because the bundled PaySim dataset lacks granular timestamps. Active production model binaries (`models/transaction_model.joblib`) remain preserved and untouched.

---

## 2. Implemented Capabilities Across All 12 Phases

```
                       [ FastAPI Server Startup ]
                                   │
                                   ▼
             ┌───────────────────────────────────────────┐
             │  Automatic CTI Collector & Scheduler     │
             │  - Single-Instance File Lock (PID Lock)   │
             │  - Provider Rate Limits & Backoff Retry   │
             └─────────────────────┬─────────────────────┘
                                   │
                                   ▼
             ┌───────────────────────────────────────────┐
             │   Ingestion, Normalization & Expiration   │
             │   - Deduplication on (type, value)        │
             │   - Expiration Purge & Auditable DB Logs  │
             └─────────────────────┬─────────────────────┘
                                   │
          ┌────────────────────────┴────────────────────────┐
          ▼                                                 ▼
[ Real-Time AUIE Matching ]                       [ Controlled Learning Pipeline ]
 (Cache Flush -> Instant Match)                    (Analyst Feedback Review Queue)
          │                                                 │
          ▼                                                 ▼
[ 4-State Reputation & Advisory ]                 [ Candidate Model Registry ]
 (Malicious, Benign, Suspicious, Unknown)          (Fail-Closed Temporal Lock)
```

### Key Technical Implementations
1. **Automatic Synchronization Lifecycle (Phase 2 & 9):** Automatically starts upon FastAPI startup (`@app.on_event("startup")`), executes initial feed synchronization, and maintains background execution.
2. **Provider State Tracking (Phase 2):** Tracks 5 distinct operational provider states (`ACTIVE`, `UNCONFIGURED`, `DEGRADED`, `FAILED`, `DISABLED`) in `auie_provider_status` and `cti_sources` database tables.
3. **Database Indicator Management & Purging (Phase 3):** Standardized indicators maintain full provenance, timestamps, confidence scores, and verification status. Executing `cti_db.purge_expired_indicators()` updates expired indicators to status `'Expired'`, preventing expired threat indicators from acting as active malicious threats.
4. **Adaptive URL Intelligence Integration (Phase 4):** Ingestion of new verified indicators triggers `cti_matcher.invalidate_cache()`, making fresh threat intelligence immediately available to AUIE URL checks.
5. **Analyst Feedback Triage & Poisoning Resistance (Phase 5):** Feedback categories (`CONFIRMED_MALICIOUS`, `FALSE_POSITIVE`, `LEGITIMATE`, `NEEDS_INVESTIGATION`) pass through an explicit analyst approval workflow (`PENDING_REVIEW`, `APPROVED`, `REJECTED`, `NEEDS_MORE_EVIDENCE`). Unapproved or user-submitted feedback CANNOT enter training datasets.
6. **Controlled ML Governance (Phase 6 & 7):** Candidate models fit RandomForest, GradientBoosting, or LogisticRegression classifiers, compute comprehensive metrics (Precision, Recall, F1-Score, ROC-AUC, PR-AUC, FPR, FNR), and register in SQLite table `cti_model_registry`. Production model activation strictly enforces deployment eligibility rules.
7. **Intelligence & Model Health Dashboard (Phase 8):** Dashboard endpoint `GET /api/intelligence/health` returns operational provider statuses, database breakdown stats, active model metadata, and feedback triage metrics.

---

## 3. Exact Files Created and Modified

### New Source Files Created
- [`upi-fraud-guard-v3/test_continuous_intelligence_learning.py`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/test_continuous_intelligence_learning.py): Phase 11 test suite covering all 20 CTI, AUIE, ML governance, and security scenarios.
- [`CONTINUOUS_INTELLIGENCE_AND_CONTROLLED_LEARNING_REPORT.md`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/CONTINUOUS_INTELLIGENCE_AND_CONTROLLED_LEARNING_REPORT.md): Final master deliverable report.

### Modified Source Files (Backed Up Before Editing)
- [`upi-fraud-guard-v3/cti_database.py`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/cti_database.py) (backed up to `cti_database.py.bak`): Added `purge_expired_indicators()`, `get_cti_database_stats()`, and `get_approved_learning_dataset()`.
- [`upi-fraud-guard-v3/cti_collector.py`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/cti_collector.py) (backed up to `cti_collector.py.bak`): Enhanced `run_now()` to purge expired indicators and invalidate `cti_matcher` cache automatically upon new indicator ingestion.
- [`upi-fraud-guard-v3/cti_api.py`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/cti_api.py) (backed up to `cti_api.py.bak`): Added `GET /api/intelligence/health` endpoint with provider health, DB stats, ML governance, and feedback triage metrics.

---

## 4. Test Results & Validation Summary

```text
Ran 20 tests in 137.504s — OK
```

- **Test Suite:** `test_continuous_intelligence_learning.py`
- **Total Tests Passed:** 20 / 20 (100%)
- **Failing / Skipped Tests:** 0

### Complete 20-Scenario Verification Matrix

| ID | Test Scenario | Verified Behavior | Verdict |
| :---: | :--- | :--- | :---: |
| **1** | Initial CTI Synchronization | CTI connectors register correctly in SQLite table `cti_sources`. | **PASS** |
| **2** | Periodic Synchronization Worker | Worker background loop executes sync passes on schedule. | **PASS** |
| **3** | Provider Failure Isolation | Individual provider lookup failures log errors without crashing worker thread. | **PASS** |
| **4** | Missing API Credentials | Unconfigured keys set status to `UNCONFIGURED` without emitting fake indicators. | **PASS** |
| **5** | Duplicate IOC Prevention | Duplicate indicators update `last_seen` and `source_count` without inserting duplicate rows. | **PASS** |
| **6** | Expired IOC Handling | Expired indicators updated to status `'Expired'` and excluded from active malicious matches. | **PASS** |
| **7** | Cache Invalidation on New Threat | Ingestion of new verified indicators invalidates `cti_matcher` cache immediately. | **PASS** |
| **8** | Background Worker Lock | File lock `cti_collector.lock` prevents concurrent duplicate worker threads. | **PASS** |
| **9** | Feedback Submission | Analysts submit feedback reports with structured evidence notes. | **PASS** |
| **10** | Feedback Review Workflow | Feedback status transitions (`PENDING_REVIEW` -> `APPROVED` / `REJECTED`) recorded with reviewer identity. | **PASS** |
| **11** | Data Poisoning Resistance | Pending or rejected feedback records cannot enter training datasets (`get_approved_learning_dataset()`). | **PASS** |
| **12** | Candidate Model Training | Candidate evaluator fits ML models and computes evaluation metrics in registry. | **PASS** |
| **13** | Fail-Closed Deployment Rejection | Candidate model deployment strictly refused for PaySim non-temporal datasets. | **PASS** |
| **14** | Model Rollback Governance | Rollback refuses activation of non-existent or corrupted model artifacts. | **PASS** |
| **15** | CTI Health Endpoint | `GET /api/intelligence/health` returns live provider statuses, DB stats, ML status, and triage counts. | **PASS** |
| **16** | RBAC Role Authorization | Administrative endpoints reject requests with invalid Bearer tokens (HTTP 401/403). | **PASS** |
| **17** | Sensitive Data Privacy | Sensitive query parameters (`pa`, `pn`, `am`, `otp`, `pin`, `token`) stripped prior to outbound calls. | **PASS** |
| **18** | AUIE 4-State Classification | AUIE engine evaluates `KNOWN_BENIGN`, `SUSPICIOUS`, `CONFIRMED_MALICIOUS`, and `UNKNOWN`. | **PASS** |
| **19** | Database Statistics Breakdown | DB queries accurately count active, verified, expired, quarantined, and category totals. | **PASS** |
| **20** | Core Fraud Engine Regression | Pre-transaction check (`POST /check`) returns accurate risk scores and explanations. | **PASS** |

---

## 5. Final Acceptance Criteria Classification

In accordance with Phase 12 guidelines, the status of all project components is classified below:

| Classification Category | Description & Included Components |
| :--- | :--- |
| **A. Fully Implemented & Tested** | • Automatic background CTI collector & file lock (`cti_collector.lock`)<br>• Multi-source indicator normalization & deduplication<br>• Expired indicator purging (`purge_expired_indicators()`)<br>• Immediate cache invalidation & AUIE threat matching<br>• Analyst feedback submission & approval workflow (`PENDING_REVIEW` -> `APPROVED`)<br>• Fail-closed candidate model deployment gate (`Refusing model deployment...`)<br>• Atomic model rollback governance<br>• Intelligence & Model Health API (`GET /api/intelligence/health`)<br>• SSRF defenses, 5 MiB payload caps, and PII parameter stripping |
| **B. Implemented but Requiring External Credentials** | • Commercial API lookups for Google Web Risk (`GOOGLE_WEB_RISK_API_KEY`), VirusTotal (`VIRUSTOTAL_API_KEY`), AlienVault OTX (`OTX_API_KEY`), and AbuseIPDB (`ABUSEIPDB_API_KEY`). Unconfigured state handled safely. |
| **C. Implemented but Awaiting Real-World Validation** | • Physical Android camera barcode decoding on physical device hardware during field pilot. |
| **D. Not Implemented** | • Uncontrolled automatic self-training (intentionally excluded per ML safety policy). |
| **E. Blocked by Missing Data or Infrastructure** | • Production deployment of newly trained transaction models is locked until a timestamped transaction log is acquired to enable temporal cross-validation. |

---

## 6. Pilot Deployment & Rollback Instructions

### Deployment Prerequisites
1. **Environment Credentials:** Copy `.env.example` to `.env` and configure commercial API keys (`GOOGLE_WEB_RISK_API_KEY`, `VIRUSTOTAL_API_KEY`, etc.) as available.
2. **Network TLS Certification:** Supply valid PEM-encoded TLS certificate and key files (`UPI_FRAUD_GUARD_TLS_CERT`, `UPI_FRAUD_GUARD_TLS_KEY`) when binding to non-loopback network interfaces (`0.0.0.0` or host IP).

### Model Rollback Procedure
If a future temporal transaction model is deployed and needs to be rolled back:
```bash
curl -X POST -H "Authorization: Bearer <ADMIN_TOKEN>" http://127.0.0.1:8000/api/intelligence/models/<ACTIVE_MODEL_ID>/rollback
```
The registry manager will atomically restore `models/active_transaction_model.json` to the previous verified artifact SHA-256 digest without server restarts.
