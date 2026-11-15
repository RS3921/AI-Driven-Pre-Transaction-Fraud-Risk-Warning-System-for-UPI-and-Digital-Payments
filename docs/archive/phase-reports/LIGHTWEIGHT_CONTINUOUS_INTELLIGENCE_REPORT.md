# LIGHTWEIGHT CONTINUOUS INTELLIGENCE REPORT
**UPI Fraud Guard Enterprise v2.6.0-RC1**

**Date:** 2026-11-10  
**Target Release Version:** `v2.6.0-RC1` (`2.6.0-Enterprise`)  
**Workspace Root:** `C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved`  
**Backend Subproject:** `upi-fraud-guard-v3`  
**Status:** VERIFIED & PASSED (100% Test Pass Rate Across 12 Test Modules)

---

## 1. Executive Summary & Existing Architecture Preserved

The **Lightweight Continuous Intelligence System** enhances UPI Fraud Guard Enterprise v2.6.0-RC1 with automatic threat-intelligence updates, real-time AUIE cache invalidation, and controlled ML improvement while maintaining an ultra-lightweight, zero-overhead architecture.

### 1. Existing Architecture Preserved (Zero Heavy Infrastructure Added)
- **Backend:** Python 3.13 + FastAPI with Uvicorn.
- **Database:** Single persistent SQLite database (`data/risk_checks.db`) with Write-Ahead Logging (WAL) mode.
- **No Heavy Infrastructure Introduced:** Strictly **NO** Redis, Kafka, Celery, Kubernetes, microservices, or secondary database clusters were added.
- **Inference Engines:** Existing AUIE 4-state engine, Scikit-learn transaction/NLP models, and CTI matcher preserved.

---

## 2. Implemented Capabilities Summary

```
                       [ FastAPI Backend Startup ]
                                   │
                                   ▼
             ┌───────────────────────────────────────────┐
             │  Automatic CTI Collector & Scheduler     │
             │  - Single-Instance File Lock (PID Lock)   │
             │  - Bounded Retries & Per-Provider Caps   │
             └─────────────────────┬─────────────────────┘
                                   │
                                   ▼
             ┌───────────────────────────────────────────┐
             │   Ingestion, Normalization & Expiration   │
             │  - Deduplication on (type, value)        │
             │  - Expiration Purging (`purge_expired`)  │
             └─────────────────────┬─────────────────────┘
                                   │
          ┌────────────────────────┴────────────────────────┐
          ▼                                                 ▼
[ Real-Time AUIE Cache Flush ]                    [ Analyst Feedback Review Queue ]
 (Instant New Threat Availability)                 (Pending -> Approved / Rejected)
          │                                                 │
          ▼                                                 ▼
[ 4-State Reputation & Advisory ]                 [ Candidate Model Registry ]
 (Malicious, Benign, Suspicious, Unknown)          (Fail-Closed Temporal Lock)
```

### Key Technical Enhancements
1. **Automatic CTI Synchronization:** Starts automatically upon FastAPI backend startup (`@app.on_event("startup")`), executes initial synchronization, and continues periodic background passes (default: 30 minutes, configurable via `CTI_COLLECTION_INTERVAL_MINUTES`).
2. **Single-Worker Locking & Deduplication:** Prevents duplicate worker passes across Uvicorn worker threads using a lightweight single-instance file lock ([`data/cti_collector.lock`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/data/cti_collector.lock)).
3. **Automatic AUIE Threat Refresh:** Ingestion of new verified indicators automatically purges `cti_matcher`'s in-memory cache, enabling AUIE URL checks to immediately match newly identified threats without requiring server restarts or model retraining.
4. **Indicator Expiration Management:** [`cti_db.purge_expired_indicators()`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/cti_database.py#L710) updates expired threat records to status `'Expired'`. Expired indicators are strictly excluded from confirmed malicious matches.
5. **Lightweight Analyst Feedback Triage:** Feedback categories (`CONFIRMED_MALICIOUS`, `FALSE_POSITIVE`, `LEGITIMATE`, `NEEDS_INVESTIGATION`) pass through an analyst approval workflow (`PENDING_REVIEW` -> `APPROVED` / `REJECTED`). Only approved, evidence-supported feedback enters versioned training datasets ([`get_approved_learning_dataset()`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/cti_database.py#L740)).
6. **Controlled ML Governance & Deployment Lock:** Candidate models fit RandomForest, GradientBoosting, or LogisticRegression classifiers and compute comprehensive metrics. Production model activation strictly enforces temporal validation rules (`Refusing model deployment: candidate lacks eligible temporal evaluation`), locking active production binaries (`models/transaction_model.joblib`) to the baseline.
7. **Real-Time Health Dashboard API:** Endpoint `GET /api/intelligence/health` returns operational provider statuses (`ACTIVE`, `UNCONFIGURED`, `DEGRADED`, `FAILED`, `DISABLED`), CTI DB statistics, active model metadata, and feedback triage metrics.

---

## 3. Exact Source Files & Test Modules

### New Source & Test Modules
- [`upi-fraud-guard-v3/test_lightweight_continuous_intelligence.py`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/test_lightweight_continuous_intelligence.py): Test suite covering all 11 lightweight intelligence, CTI, AUIE, ML governance, and security scenarios.
- [`LIGHTWEIGHT_CONTINUOUS_INTELLIGENCE_REPORT.md`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/LIGHTWEIGHT_CONTINUOUS_INTELLIGENCE_REPORT.md): Final master deliverable report.

### Core Implementation Files
- [`upi-fraud-guard-v3/cti_database.py`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/cti_database.py): Managed SQLite tables for sources, indicators, provider statuses, feed sync, analysis history, feedback triage, and model registry.
- [`upi-fraud-guard-v3/cti_collector.py`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/cti_collector.py): Background scheduler with file locking, backoff retries, and automatic cache invalidation.
- [`upi-fraud-guard-v3/cti_api.py`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/cti_api.py): FastAPI REST endpoints for CTI, AUIE, and health metrics.

---

## 4. Test Execution Summary

```text
Ran 11 tests in 83.053s — OK
```

- **Test Suite:** `test_lightweight_continuous_intelligence.py`
- **Total Tests Passed:** 11 / 11 (100% Pass Rate)
- **Failing / Skipped Tests:** 0
- **Global Regression Suite:** All 12 test modules across the workspace passed without any failures.

---

## 5. Performance & Resource Consumption Impact

- **CPU / RAM Impact:** Negligible. The background collector thread sleeps for 30 minutes between cycles and uses standard Python threads for connector fetches.
- **Database Overhead:** SQLite Write-Ahead Logging (WAL) mode prevents database lock contention between background collector writes and live `/check` read queries.
- **Network Efficiency:** Per-provider request timeouts (2.0s cap) and response byte budget caps (5 MiB max) prevent network congestion or thread pool exhaustion.

---

## 6. Pilot Deployment & Rollback Instructions

### Staging / Pilot Setup
1. Copy `.env.example` to `.env` and configure commercial API keys (`GOOGLE_WEB_RISK_API_KEY`, `VIRUSTOTAL_API_KEY`, etc.) as available.
2. Start the backend API server:
   ```bash
   cd upi-fraud-guard-v3
   python run_api.py
   ```

### Model Rollback Procedure
If a future temporal transaction model is deployed and requires rollback:
```bash
curl -X POST -H "Authorization: Bearer <ADMIN_TOKEN>" http://127.0.0.1:8000/api/intelligence/models/<ACTIVE_MODEL_ID>/rollback
```
Restores `models/active_transaction_model.json` to the previous verified artifact SHA-256 digest without server restarts.
