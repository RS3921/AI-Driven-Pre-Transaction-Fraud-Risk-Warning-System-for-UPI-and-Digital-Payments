# Release Notes — UPI Fraud Guard Enterprise v2.6.0-RC1

**Release Tag:** `v2.6.0-RC1` (Release Candidate 1)  
**Target Environment:** Controlled Staging / Pilot Testing  
**Release Date:** 2026-11-10  
**Baseline Git/Directory:** `UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3`

---

## 1. Overview

UPI Fraud Guard Enterprise is an explainable multimodal pre-transaction fraud risk intelligence platform for Unified Payments Interface (UPI) ecosystems. It correlates signals across SMS/messaging analysis (multilingual Devanagari/English NLP), URL/QR lexical and cryptographic analysis, behavioral transaction anomaly modeling, and Cyber Threat Intelligence (CTI).

Version `v2.6.0-RC1` marks the successful remediation and stabilization of critical CTI ingestion security, dataset provenance transparency, model registry governance, and dashboard integrity.

---

## 2. Key Features & Remediation Highlights

### 🛡️ Cyber Threat Intelligence (CTI) Ingestion & Security
- **Elimination of Fake Fallback IOCs**: Source connectors fail closed on upstream network outages or missing API keys, logging explicit failure/unconfigured states rather than emitting synthetic demo indicators.
- **SSRF & DNS-Pinning Protection**: Outbound CTI collection strictly resolves and binds sockets to verified global IPs (`_PinnedHTTPConnection`), mitigating DNS rebinding and TOCTOU attacks.
- **Resource Bounds & Header Stripping**: Implemented a hard streaming limit of 5 MiB on external HTTP responses and automated credential stripping during cross-host redirects.
- **Allowlist & Normalization Pipeline**: Integrated canonicalization, domain allowlisting, and syntax validation directly into collection.
- **Strict Verification Gating**: Indicators are matched only if marked `Verified Malicious`, unexpired, and non-quarantined. High confidence scores alone cannot bypass verification.

### 🧠 Model Governance & Continuous ML Pipeline
- **Dataset Provenance Transparency**: Training is bound to real ground-truth data (`data/transactions_dataset.csv`, 268,215 PaySim-derived rows).
- **Fail-Closed Deployment Policy**: Candidate models require explicit temporal validation. Because PaySim lacks granular real-world timestamps, candidate models are refused production deployment (`deployment_eligible: False`), preventing unvalidated models from replacing production weights.
- **Hot-Swapping & Rollback**: Runtime active model pointer (`active_transaction_model.json`) allows zero-downtime hot-swapping and audited rollbacks with cryptographic SHA-256 validation.

### 🌐 Multimodal Detection & Multilingual Support
- **Full Multilingual Heuristics**: Preserved English, Hindi, Marathi, and Hinglish scam detection rules and SHAP explainability.
- **Message Pattern Intelligence**: Integrated CTI message-pattern matching directly into the main risk scoring engine.

### 🔒 Enterprise Dashboard & API Security
- **Bearer Token Authentication**: Configurable via `UPI_FRAUD_GUARD_API_USERS`.
- **Role-Based Access Control (RBAC)**: Enforces permissions for `super_admin`, `fraud_analyst`, `investigation_officer`, and `read_only_auditor`.
- **DOM XSS Mitigation**: All untrusted data fields are sanitized via `escapeHtml()` prior to DOM rendering.
- **Android Client Contract Compatibility**: Verified 100% schema alignment with Android client data classes.

---

## 3. Verification & Test Metrics

- **Unit & Integration Tests:** 48 passed out of 48 executed across 7 suites (`Ran 48 tests in ~314s — OK`).
- **Independent Verification:** 10/10 technical audit criteria verified.
- **Code Coverage Areas:** CTI adapters, SSRF security, extraction/normalization, matching trust gates, candidate ML training, registry approval/rollback, API contracts, dashboard security, and graph mule detection.

---

## 4. Known Limitations & Production Prerequisites

1. **Simulated Transaction Data**: Base transaction models are trained on PaySim simulated mobile-money data, not live bank transaction records.
2. **Temporal Validation Blocker**: Real-world production deployment of candidate models is intentionally blocked until a timestamped production dataset is provided.
3. **External CTI Credentials**: Live feeds for AbuseIPDB and AlienVault OTX require valid subscription keys.
4. **Transport Layer Security**: Binding to non-loopback addresses requires TLS certificates (`UPI_FRAUD_GUARD_TLS_CERT` and `UPI_FRAUD_GUARD_TLS_KEY`).
