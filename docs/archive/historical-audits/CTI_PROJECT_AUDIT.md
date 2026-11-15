# AUTONOMOUS CTI & CONTINUOUS LEARNING ENGINE — PHASE 1 AUDIT REPORT

**Project Name:** UPI Fraud Guard  
**Engine Module:** Autonomous Cyber Threat Intelligence (CTI) & Continuous Learning Engine  
**Version Target:** 3.0.0-Enterprise-CTI  
**Date:** March 2026  
**Auditor Persona:** Senior Python Backend Engineer, CTI Researcher, ML Engineer & Security Architect  

---

## 1. Existing System Architecture Overview

The current **UPI Fraud Guard** workspace consists of two primary operational components:

1. **FastAPI Backend Server (`upi-fraud-guard-v3/`)**:
   - `api/main.py`: Core FastAPI REST application with routes for `/check`, `/scan-qr`, `/history`, `/analytics`, `/status`, `/feed-status`, `/mule-analysis`, `/investigations`, `/model-monitoring`.
   - `api/security.py`: Token authentication & RBAC (`super_admin`, `fraud_analyst`, `investigation_officer`, `read_only_auditor`).
   - `dual_feed.py`: Static Dual-Feed threat loader (reads static files `phishtank_feed.txt`, `openphish_feed.txt` and hardcoded VPA list).
   - `mule_detection.py`: NetworkX graph-based mule account detector.
   - `investigation.py`: SQLite-backed case queue (`investigations` table).
   - `model_monitor.py` & `evaluate_models.py`: Statistical drift monitoring and model baseline comparison.
   - `risk_fusion.py`: 0–100 risk score calculator and 4-tier decision engine (`Low`, `Medium`, `High`, `Critical`).

2. **Android Native Client (`upi-fraud-guard-android/`)**:
   - Kotlin / Jetpack Compose application with 5 tabs, 2FA QR code generator, and compulsory Notification Access setup flow.

---

## 2. Technical Gap & Vulnerability Analysis

The current platform lacks an **autonomous, continuous threat intelligence collection and model learning pipeline**:

### Gap 1: Absence of Autonomous Background Collection Worker
- **Current State**: `dual_feed.py` reads local static text files once at initialization.
- **Defect**: No background scheduler automatically ingests new threat intelligence while the backend runs.
- **Required Solution**: Build an asynchronous background collector (`cti_collector.py`) that initializes at FastAPI startup, runs every 30 minutes (configurable via `CTI_COLLECTION_INTERVAL_MINUTES`), supports manual trigger, handles exponential backoff, and avoids duplicate execution.

### Gap 2: Missing Source Connectors (Indian & Global Threat Intelligence)
- **Current State**: No live source connectors exist.
- **Defect**: The platform cannot collect emerging Indian cybercrime advisories or global threat feeds automatically.
- **Required Solution**: Develop resilient, independent connectors in `cti_connectors.py`:
  - *Indian Cybersecurity*: CERT-In advisories (RSS/HTML), NPCI UPI security circulars, RBI fraud notifications, Cybercrime advisories.
  - *Global Threat Intelligence*: PhishTank API, URLhaus API, OpenPhish feed, AlienVault OTX, AbuseIPDB, CISA KEV catalog, MITRE ATT&CK techniques.

### Gap 3: Lack of Intelligence Extraction, Normalization & Verification Pipeline
- **Current State**: Raw URLs from text files are loaded without structured indicator classification or confidence scoring.
- **Defect**: Indicators are un-categorized and cannot represent fraud patterns (Fake KYC, Collect Request Fraud, QR Replacement, OTP Harvesting).
- **Required Solution**: Develop `cti_extraction.py` & `cti_normalization.py` to extract:
  - Technical Indicators: URLs, Domains, IPs, Hashes, Emails, VPAs, Redirects.
  - Fraud Patterns: Fake KYC, OTP Harvesting, Impersonation, Collect Request Fraud, QR Replacement, Remote Access Scams, Cashback/Job Fraud.
  - Verification Statuses: `Verified Malicious`, `Reported Unverified`, `Suspicious`, `Benign/Allowlisted`, `Expired`.
  - Canonicalization, domain normalization, IP validation, confidence scoring (0–100), and indicator expiry tracking.

### Gap 4: Incomplete Database Storage Schema
- **Current State**: Database (`risk_checks.db`) contains only `risk_checks` and `investigations` tables.
- **Defect**: No database tables exist to store threat indicators, collection logs, fraud patterns, model registry, or audit trails.
- **Required Solution**: Create SQLite tables in `cti_database.py`:
  - `cti_indicators` (indicator_id, value, type, category, confidence, verification_status, evidence, expiry, etc.)
  - `cti_sources` (source_name, source_type, last_sync, status, fetched_count, error_count)
  - `cti_collection_logs` (log_id, source_name, timestamp, records_fetched, status, error_details)
  - `cti_fraud_patterns` (pattern_id, pattern_name, description, attack_vectors, mitre_tactics)
  - `cti_indicator_reviews` (review_id, indicator_id, reviewer, status_change, notes, timestamp)
  - `cti_model_registry` (model_id, name, version, trained_at, dataset_version, metrics, approval_status, is_active)

### Gap 5: Missing Integration with Fraud Detection Modules
- **Current State**: Fraud detection modules evaluate inputs in isolation without querying verified CTI records.
- **Defect**: Known malicious indicators in CTI are not automatically surfaced in check results.
- **Required Solution**: Update `score_message()`, `analyse_url()`, QR decoder, and `fuse()` to query verified CTI indicators, adding CTI evidence, source references, and confidence scores without double-counting.

### Gap 6: Absence of Quality-Controlled Continuous ML Training Pipeline
- **Current State**: Model training is manually invoked via command line scripts.
- **Defect**: No continuous candidate model training pipeline exists.
- **Required Solution**: Build `cti_ml_pipeline.py`:
  - Prepares quality-controlled, validated datasets (separating verified malicious, verified benign, and synthetic examples; NEVER training blindly on raw unverified web data!).
  - Trains candidate models, evaluates metrics (Precision, Recall, F1, ROC-AUC, PR-AUC, Confusion Matrix).
  - Registers candidates in `cti_model_registry` requiring human approval (`/approve`) before deployment, with full rollback capability (`/rollback`).

### Gap 7: Missing SSRF & Security Guardrails for External Ingestion
- **Current State**: URL analyzer lacks strict SSRF blocking for private IP ranges.
- **Defect**: External fetching could potentially hit internal/cloud metadata addresses.
- **Required Solution**: Build `cti_security.py`:
  - SSRF protection: Blocks localhost, `127.0.0.1`, private IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and cloud metadata (`169.254.169.254`).
  - Request timeouts (10s), size limits (5 MB), content sanitization, and strictly isolated execution.

### Gap 8: Missing Autonomous Intelligence Centre Frontend Dashboard Tab
- **Current State**: Web dashboard contains Overview, Feeds, Mule Graph, Investigations, and Model Drift tabs.
- **Defect**: No dedicated UI section exists to monitor autonomous collection, explore indicators, review CTI logs, or approve ML models.
- **Required Solution**: Build the **Autonomous Intelligence Centre** tab in `frontend/index.html` & `frontend/script.js`:
  - CTI Overview Metrics (Total Collected, Verified Malicious, Suspicious, Source Health).
  - Source Collection Monitor (Status, Last Sync, Next Run, Fetched Records, Error Logs).
  - Threat Indicator Explorer (Search, Filter by Category/Confidence, View Evidence, Review/Validate Button).
  - ML Model Registry & Approval Controls (Active Model vs Candidate Model comparison, Precision/Recall metrics, Approve & Rollback buttons).
  - CTI Audit Logs.

---

## 3. Implementation Plan & Phase Roadmap

```
PHASE 1: Project & Architecture Audit (COMPLETED)
  └── Complete CTI_PROJECT_AUDIT.md report and gap analysis.

PHASE 2: Intelligence Infrastructure & Schema Layer
  ├── Create cti_database.py (SQLite schema for indicators, sources, logs, registry).
  ├── Create cti_security.py (SSRF protection, size limits, safe timeouts).
  ├── Create cti_connectors.py (CERT-In, NPCI, RBI, PhishTank, URLhaus, OpenPhish, CISA KEV, MITRE ATT&CK, AbuseIPDB, AlienVault OTX).
  └── Create cti_collector.py (Async background worker & scheduler with lock).

PHASE 3: Extraction, Normalization & Verification Pipeline
  ├── Create cti_extraction.py (Extract technical indicators & fraud patterns).
  ├── Create cti_normalization.py (Canonicalization, validation, confidence scoring, expiry).
  └── Create cti_api.py (REST endpoints for status, sources, indicators, review, collection logs).

PHASE 4: Fraud Detection Engine Integration
  ├── Update score_message(), analyse_url(), QR decoder, and fuse() to query CTI indicators.
  └── Provide explainable CTI threat evidence in check results.

PHASE 5: Quality-Controlled Continuous ML Pipeline & Model Registry
  ├── Create cti_ml_pipeline.py (Dataset preparation, candidate model training, evaluation).
  └── Add Model Registry endpoints (/models, /evaluations, /approve, /rollback).

PHASE 6: Autonomous Intelligence Centre Frontend Dashboard
  ├── Update frontend/index.html (Autonomous CTI tab with Explorer & Model Registry).
  └── Update frontend/script.js (Live CTI API data bindings & action handlers).

PHASE 7: Automated Testing, DevOps & Security Review
  ├── Create test_cti_engine.py (Unit & integration tests with mocked APIs).
  └── Update documentation (IMPLEMENTATION_REPORT.md, SECURITY_REVIEW.md, TEST_REPORT.md, README.md).
```

---

## 4. Audit Verdict & Recommendation

The existing workspace is highly structured, modular, and fully functional. The implementation of the **Autonomous CTI & Continuous Learning Engine** will be built seamlessly on top of the existing FastAPI infrastructure without breaking any existing endpoints, Android client contracts, or database retention policies.

*Phase 1 Audit Report is ready for review and approval before proceeding to Phase 2.*
