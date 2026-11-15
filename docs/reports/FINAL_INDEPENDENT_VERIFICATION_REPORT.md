# FINAL INDEPENDENT VERIFICATION REPORT
**UPI Fraud Guard — Post-Remediation Security & Architecture Verification**

**Verification Date:** 2026-11-10  
**Scope:** `upi-fraud-guard-v3` backend, `upi-fraud-guard-android` client contracts, and documentation  
**Mode:** Independent Verification-Only (Read-Only across all code, models, data, and configurations)

---

## 1. Executive Assessment

An independent line-by-line verification was conducted across the codebase of **UPI Fraud Guard** to evaluate the remediated implementation against the claims made in [CRITICAL_REMEDIATION_REPORT.md](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/CRITICAL_REMEDIATION_REPORT.md), [CTI_ARCHITECTURE.md](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/CTI_ARCHITECTURE.md), [MODEL_GOVERNANCE.md](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/MODEL_GOVERNANCE.md), and [SECURITY_REVIEW.md](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/SECURITY_REVIEW.md).

All 48 tests across 7 test suites were executed without modifying code or test fixtures, completing with zero failures:
```text
Ran 48 tests in 314.887s — OK
```

The remediation is verified to be technically authentic:
- Static/demo fallback IOC generation on network or credential failures has been completely eliminated.
- Outbound HTTP fetching enforces pinned-IP socket connections, host allowlists, credential stripping, and streaming byte caps.
- IOC matching enforces verification status, expiry timestamps, and quarantine filters.
- Multilingual threat heuristics and SHAP explainability remain intact.
- Model governance enforces a fail-closed production deployment policy when dataset temporal features are absent.

---

## 2. Itemized Claim-by-Claim Verification

### Item 1: CTI Connectors & Data Provenance
- **Report Claim:** All connectors distinguish live intelligence, static reference data, synthetic test data, and failed/unconfigured sources without emitting fake fallback IOCs.
- **Actual Implementation Inspected:** In [`cti_connectors.py`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/cti_connectors.py#L90), `BaseSourceConnector.collect()` checks `self.api_key_env` via `get_environment_secret()`. If missing, it immediately sets status to `"Unconfigured"` without attempting network calls or persisting fallback indicators. On network or parsing errors, the catch block updates source sync status to `"Failed"`, logs the error, and inserts 0 indicators. Knowledge-base connectors like `CisaKevConnector` and `MitreAttackConnector` emit `_non_indicator` types to prevent non-IOC data from being forced into indicator types.
- **File and Function:** `cti_connectors.py`: `BaseSourceConnector.collect()`, `CertInConnector.fetch_records()`, `AbuseIpdbConnector.fetch_records()`.
- **Verification Method:** Static code inspection and execution of `test_failed_source_does_not_insert_fallback` and `test_missing_credentials_are_unconfigured` in `test_critical_remediations.py`.
- **Verdict:** **PASS**
- **Remaining Risk:** Upstream live feeds (e.g., CERT-In RSS, NPCI web endpoints) may alter their markup or return HTTP 403 blocks; error handling is robust, but source sync logs will show `Failed` until feed endpoints are updated.

---

### Item 2: Secure External HTTP Fetching (SSRF, DNS, Limits, Redirects)
- **Report Claim:** Secure fetching with DNS pinning, redirect host validation, sensitive credential stripping, private/cloud-metadata blocking, and 5 MiB streaming limit enforcement.
- **Actual Implementation Inspected:** In [`cti_security.py`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/cti_security.py#L40), `_resolve_public()` resolves hostnames and checks all returned socket addresses against `ip.is_global`. Custom `_PinnedHTTPConnection` and `_PinnedHTTPSConnection` classes override `connect()` to establish sockets directly to the pre-validated `sockaddr`. In `fetch_secure_content()`, redirect hops (up to 5) re-validate URLs against `ALLOWED_SOURCE_HOSTS` and strip `SENSITIVE_HEADERS` (`authorization`, `key`, `x-otx-api-key`) if the host changes. Responses are read in 64 KiB chunks with a hard 5 MiB threshold (`MAX_RESPONSE_BYTES`).
- **File and Function:** `cti_security.py`: `_resolve_public()`, `validate_url_security()`, `fetch_secure_content()`.
- **Verification Method:** Unit test execution of `test_cross_host_redirect_does_not_forward_credentials`, `test_streaming_limit_rejects_chunked_oversize_body`, `test_pinned_fetch_uses_resolved_ip`, and `test_05_response_size_limit_enforcement`.
- **Verdict:** **PASS**
- **Remaining Risk:** None for outbound connector fetching. When feeds redirect to secondary CDNs (e.g., PhishTank redirecting to `cdn.phishtank.com`), the target domain must be explicitly added to `ALLOWED_SOURCE_HOSTS` or the fetch is safely blocked.

---

### Item 3: Complete Extraction-to-Matching Pipeline
- **Report Claim:** Connects Source Retrieval → Extraction → Normalization → Validation → Deduplication → Persistence → Verification → Matching.
- **Actual Implementation Inspected:** In [`cti_connectors.py`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/cti_connectors.py#L105), rows from `fetch_records()` pass through `self._normalize()` which validates syntax and canonicalizes URLs/domains/IPs/hashes/emails/VPAs. Values are checked against domain allowlists in `intelligence_normalizer.calculate_confidence_and_status()`. Deduplication occurs in `cti_db.add_indicator()`, updating `last_seen` and source attribution while preserving original provenance.
- **File and Function:** `cti_connectors.py` (`collect()`, `_normalize()`), `cti_normalization.py` (`canonicalize_url()`, `calculate_confidence_and_status()`), `cti_database.py` (`add_indicator()`).
- **Verification Method:** Execution of `test_cti_phase3.py` (all 7 tests) and `test_retrieved_advisory_content_is_extracted_and_stored_unverified`.
- **Verdict:** **PASS**
- **Remaining Risk:** Unstructured text feeds rely on regex extraction; zero-day phishing obfuscations (e.g. custom hex encodings in query strings) may bypass regex without lexical preprocessing.

---

### Item 4: IOC Trust, Matching Policy & Cache Invalidation
- **Report Claim:** Expired, unverified, and quarantined indicators cannot trigger confirmed malicious matches; high confidence alone does not establish malicious status; caches invalidate on analyst review.
- **Actual Implementation Inspected:** In [`cti_matcher.py`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/cti_matcher.py#L25), `_get_verified_indicators()` filters indicators from SQLite with `verification_status="Verified Malicious"`, discards records where `quarantined=1`, and checks `expiry_dt <= current`. In `cti_normalization.py`, high confidence without `source_verified=True` assigns `Reported Unverified` or `Suspicious`. In `cti_api.py`, `review_cti_indicator()` and `quarantine_indicator()` explicitly call `cti_matcher.invalidate_cache(indicator_id)`.
- **File and Function:** `cti_matcher.py`: `_get_verified_indicators()`, `invalidate_cache()`, `match_url_or_domain()`, `match_vpa()`, `match_message_patterns()`.
- **Verification Method:** Execution of `test_confidence_alone_does_not_verify`, `test_04_expired_indicator_ignored`, and `test_07_indicator_manual_review_api`.
- **Verdict:** **PASS**
- **Remaining Risk:** Matcher cache holds active indicators for up to 30 seconds between database queries for performance; manual review actions flush the cache immediately, but expiration is re-evaluated during cache refresh.

---

### Item 5: Multilingual Fraud Detection Regression
- **Report Claim:** Multilingual message fraud detection across English, Hindi, Marathi, and Hinglish remains active and integrated with CTI pattern intelligence.
- **Actual Implementation Inspected:** In [`multilingual_message_rules.py`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/multilingual_message_rules.py#L12), unicode regex patterns cover English, Devanagari, and Indic scripts for credentials, urgent threats, and money lures. In [`api/main.py`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/api/main.py#L105), `score_message()` calls `analyse_multilingual_message()` alongside the TF-IDF NLP model, then queries `cti_matcher.match_message_patterns()`. If a verified CTI pattern matches, the risk score is boosted to at least 0.88 with explicit evidence reason attribution.
- **File and Function:** `api/main.py`: `score_message()`; `multilingual_message_rules.py`: `analyse_multilingual_message()`.
- **Verification Method:** Execution of `test_suite.py` (`test_03_pre_transaction_check_safe`, `test_04_pre_transaction_check_threat_vpa`), verifying that benign messages remain clear while scam messages trigger alerts.
- **Verdict:** **PASS**
- **Remaining Risk:** Rule-based keyword matching cannot capture complex adversarial paraphrasing or novel transliterated slang not present in vocabulary tables.

---

### Item 6: PaySim-Derived Dataset Provenance & Transparency
- **Report Claim:** Dataset provenance is transparently documented as simulated mobile-money data, and temporal limitations are documented.
- **Actual Implementation Inspected:** [`data/TRANSACTION_DATA_README.md`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/data/TRANSACTION_DATA_README.md) explicitly states: *"PaySim is simulated mobile-money data, not actual bank transaction records... Packaged metrics are benchmarks, not guarantees."* In [`cti_ml_pipeline.py`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/cti_ml_pipeline.py#L40), `DatasetPreparer` loads `transactions_dataset.csv` and sets `"evaluation_mode": "grouped_random_holdout", "temporal_evaluation": False`.
- **File and Function:** `cti_ml_pipeline.py`: `DatasetPreparer.prepare_dataset()`, `CandidateModelEvaluator.train_and_evaluate()`.
- **Verification Method:** Code and documentation inspection; verification of pipeline output dictionary metadata.
- **Verdict:** **PASS**
- **Remaining Risk:** None regarding disclosure. The data cannot be represented as genuine UPI banking traffic.

---

### Item 7: Model Governance, Eligibility & Runtime Activation
- **Report Claim:** Candidate models are audited; unverified models cannot be deployed; deployment and rollback atomically change the actual active model artifact loaded by the inference engine.
- **Actual Implementation Inspected:** In [`cti_ml_pipeline.py`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/cti_ml_pipeline.py#L145), `deploy_model()` checks that the candidate is `Approved`, verifies artifact SHA-256 integrity, verifies feature schema compatibility, and strictly requires `"temporal_evaluation": True` and `"deployment_eligible": True`. Because the PaySim dataset lacks temporal sequences, deployment attempts safely fail closed (`Refusing model deployment: candidate lacks eligible temporal evaluation`). In [`transaction_module/analyzer.py`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/transaction_module/analyzer.py#L65), `activate_runtime_model()` updates `active_transaction_model.json` atomically and hot-swaps `_txn_model` in memory.
- **File and Function:** `cti_ml_pipeline.py`: `ModelRegistryManager.deploy_model()`, `ModelRegistryManager.rollback_model()`; `transaction_module/analyzer.py`: `activate_runtime_model()`.
- **Verification Method:** Execution of `test_cti_phase5.py` (`test_03_model_approval_and_deployment_workflow`, `test_04_model_version_rollback`), asserting that unverified deployments are refused and previous models are preserved.
- **Verdict:** **PASS**
- **Remaining Risk:** Real production deployment of new transaction models is locked until a temporally ordered transaction log is acquired and evaluated.

---

### Item 8: Dashboard Security, Authentication & XSS Defenses
- **Report Claim:** Bearer token authentication, backend RBAC enforcement, and safe DOM rendering with HTML escaping.
- **Actual Implementation Inspected:** In [`frontend/script.js`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/frontend/script.js#L5), `apiFetch()` attaches `Authorization: Bearer <token>` from `sessionStorage`. `applyRole()` toggles UI controls based on session role. In [`frontend/script.js`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/frontend/script.js#L205), `escapeHtml()` sanitizes all rendered variables (indicator values, descriptions, sources, statuses, logs, case notes, model tags) before template interpolation. In [`api/security.py`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/api/security.py#L75), `require_role()` dependency enforces 403 Forbidden responses on unauthorized backend requests regardless of frontend client state.
- **File and Function:** `frontend/script.js`: `apiFetch()`, `escapeHtml()`, `applyRole()`; `api/security.py`: `require_role()`, `current_user_id()`.
- **Verification Method:** Static analysis of all `innerHTML` sinks in `frontend/script.js` and execution of `test_cti_phase6.py`.
- **Verdict:** **PASS**
- **Remaining Risk:** If an analyst pastes raw HTML in manual review notes, it will render as escaped text rather than formatted HTML, which is the correct defensive posture.

---

### Item 9: Secrets & Configuration Management
- **Report Claim:** Sensitive credentials, tokens, and API keys are not hardcoded or exposed in logs.
- **Actual Implementation Inspected:** Inspecting `.env.example`, `api/security.py`, and `cti_security.py` confirms that API keys (`ABUSEIPDB_API_KEY`, `OTX_API_KEY`, `UPI_FRAUD_GUARD_API_USERS`) are read exclusively from environment variables via `os.environ.get()`. `SENSITIVE_HEADERS` are stripped during HTTP redirection. Git tracking is configured without committed production secret files.
- **File and Function:** `cti_security.py`: `get_environment_secret()`, `SENSITIVE_HEADERS`; `api/security.py`: `_user_token_hashes()`.
- **Verification Method:** Grep search for hardcoded secrets and environment variable loading verification.
- **Verdict:** **PASS**
- **Remaining Risk:** Developers must ensure real secrets are injected securely via container environment variables or secrets managers during production deployment.

---

### Item 10: Android Client Contract Compatibility
- **Report Claim:** Android application integration and backend API contracts have not been broken.
- **Actual Implementation Inspected:** The Android client models in [`ApiModels.kt`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-android/app/src/main/java/com/upifraudguard/app/data/ApiModels.kt#L10) expect:
  - `RiskCheckRequest`: `message`, `url_or_qr`, `amount`, `recipient`, `payments_last_hour`, `is_new_recipient`.
  - `RiskCheckResponse`: `verdict`, `risk_score`, `reasons`, `modules_used`, `module_scores`, `shap_explanations`, `upi_qr_details`.
  
  In [`api/main.py`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/api/main.py#L210), `POST /check` returns precisely these fields. The addition of internal CTI evidence is merged seamlessly into `reasons` and `risk_score` without altering field names or types.
- **File and Function:** `api/main.py`: `check()`; Android `RiskGuardApi.kt`, `ApiModels.kt`.
- **Verification Method:** Schema cross-verification between Kotlin data classes and FastAPI endpoint return dictionaries, plus `test_03_pre_transaction_check_safe` and `test_04_pre_transaction_check_threat_vpa`.
- **Verdict:** **PASS**
- **Remaining Risk:** None; Android client remains completely compatible.

---

## 3. Raw Test Execution Output

The test suite was executed in an isolated terminal session on the project workspace:

```text
======================================================================
TEST RUN SUMMARY
Command: python -m unittest test_critical_remediations.py test_cti_phase2.py test_cti_phase3.py test_cti_phase4.py test_cti_phase5.py test_cti_phase6.py test_suite.py
Directory: C:\Users\Raveena\Downloads\UPI-Fraud-Guard\UPI-Fraud-Guard-Multilingual-Improved\upi-fraud-guard-v3

test_confidence_alone_does_not_verify (test_critical_remediations.TestCriticalRemediations) ... ok
test_cross_host_redirect_does_not_forward_credentials (test_critical_remediations.TestCriticalRemediations) ... ok
test_failed_source_does_not_insert_fallback (test_critical_remediations.TestCriticalRemediations) ... ok
test_missing_credentials_are_unconfigured (test_critical_remediations.TestCriticalRemediations) ... ok
test_pinned_fetch_uses_resolved_ip (test_critical_remediations.TestCriticalRemediations) ... ok
test_private_ipv4_ipv6_localhost_and_metadata_are_rejected (test_critical_remediations.TestCriticalRemediations) ... ok
test_retrieved_advisory_content_is_extracted_and_stored_unverified (test_critical_remediations.TestCriticalRemediations) ... ok
test_streaming_limit_rejects_chunked_oversize_body (test_critical_remediations.TestCriticalRemediations) ... ok

test_01_database_initialization (test_cti_phase2.TestCTIPhase2Infrastructure) ... ok
test_02_duplicate_indicator_prevention (test_cti_phase2.TestCTIPhase2Infrastructure) ... ok
test_03_ssrf_blocking_localhost_and_private_ips (test_cti_phase2.TestCTIPhase2Infrastructure) ... ok
test_04_valid_public_url_validation (test_cti_phase2.TestCTIPhase2Infrastructure) ... ok
test_05_response_size_limit_enforcement (test_cti_phase2.TestCTIPhase2Infrastructure) ... ok
test_06_source_connector_resilience (test_cti_phase2.TestCTIPhase2Infrastructure) ... ok
test_07_worker_lifecycle (test_cti_phase2.TestCTIPhase2Infrastructure) ... ok

test_01_indicator_extraction (test_cti_phase3.TestCTIPhase3ExtractionAndAPI) ... ok
test_02_canonicalization_and_normalization (test_cti_phase3.TestCTIPhase3ExtractionAndAPI) ... ok
test_03_syntax_validation (test_cti_phase3.TestCTIPhase3ExtractionAndAPI) ... ok
test_04_confidence_and_corroboration (test_cti_phase3.TestCTIPhase3ExtractionAndAPI) ... ok
test_05_allowlist_filtering (test_cti_phase3.TestCTIPhase3ExtractionAndAPI) ... ok
test_06_cti_api_endpoints (test_cti_phase3.TestCTIPhase3ExtractionAndAPI) ... ok
test_07_indicator_manual_review_api (test_cti_phase3.TestCTIPhase3ExtractionAndAPI) ... ok

test_01_url_cti_indicator_matching (test_cti_phase4.TestCTIPhase4FraudEngineIntegration) ... ok
test_02_qr_vpa_cti_indicator_matching (test_cti_phase4.TestCTIPhase4FraudEngineIntegration) ... ok
test_03_transaction_recipient_cti_matching (test_cti_phase4.TestCTIPhase4FraudEngineIntegration) ... ok
test_04_expired_indicator_ignored (test_cti_phase4.TestCTIPhase4FraudEngineIntegration) ... ok
test_05_risk_fusion_cti_evidence (test_cti_phase4.TestCTIPhase4FraudEngineIntegration) ... ok
test_06_database_offline_resilience (test_cti_phase4.TestCTIPhase4FraudEngineIntegration) ... ok

test_01_dataset_preparation (test_cti_phase5.TestCTIPhase5MLPipeline) ... ok
test_02_candidate_model_training (test_cti_phase5.TestCTIPhase5MLPipeline) ... ok
test_03_model_approval_and_deployment_workflow (test_cti_phase5.TestCTIPhase5MLPipeline) ... ok
test_04_model_version_rollback (test_cti_phase5.TestCTIPhase5MLPipeline) ... ok
test_05_model_registry_api (test_cti_phase5.TestCTIPhase5MLPipeline) ... ok

test_01_static_frontend_assets (test_cti_phase6.TestCTIPhase6DashboardIntegration) ... ok
test_02_cti_overview_data (test_cti_phase6.TestCTIPhase6DashboardIntegration) ... ok
test_03_manual_collection_trigger (test_cti_phase6.TestCTIPhase6DashboardIntegration) ... ok
test_04_threat_indicator_explorer (test_cti_phase6.TestCTIPhase6DashboardIntegration) ... ok
test_05_analyst_review_workflow (test_cti_phase6.TestCTIPhase6DashboardIntegration) ... ok
test_06_model_registry_control_panel (test_cti_phase6.TestCTIPhase6DashboardIntegration) ... ok
test_07_collection_logs_api (test_cti_phase6.TestCTIPhase6DashboardIntegration) ... ok

test_01_health_and_status (test_suite.TestUpiFraudGuardEnterprise) ... ok
test_02_dual_feed_status (test_suite.TestUpiFraudGuardEnterprise) ... ok
test_03_pre_transaction_check_safe (test_suite.TestUpiFraudGuardEnterprise) ... ok
test_04_pre_transaction_check_threat_vpa (test_suite.TestUpiFraudGuardEnterprise) ... ok
test_05_mule_analysis (test_suite.TestUpiFraudGuardEnterprise) ... ok
test_06_investigations_workflow (test_suite.TestUpiFraudGuardEnterprise) ... ok
test_07_model_monitoring (test_suite.TestUpiFraudGuardEnterprise) ... ok
test_08_threat_vpa_addition (test_suite.TestUpiFraudGuardEnterprise) ... ok

----------------------------------------------------------------------
Ran 48 tests in 314.887s

OK
```

---

## 4. Assessment of Mocks vs. Live Behavioral Verification

An essential aspect of this independent review was evaluating whether tests rely on excessive mocking or genuinely exercise security enforcement:

1. **SSRF & DNS Validation**:
   - `test_private_ipv4_ipv6_localhost_and_metadata_are_rejected` tests `validate_url_security()` directly without mocks, asserting exceptions across loopback (`127.0.0.1`), RFC 1918 private IPs (`10.0.0.1`), IPv6 loopback (`::1`), link-local (`fe80::1`), and cloud metadata (`169.254.169.254`).
   - `test_pinned_fetch_uses_resolved_ip` spins up a live local HTTP server (`ThreadingHTTPServer`), overrides only the external host resolver to return `127.0.0.1`, and intercepts `socket.create_connection` to confirm that the connection was established directly to the resolved IP rather than delegating DNS to standard libraries.
2. **Response Size Limits**:
   - `test_streaming_limit_rejects_chunked_oversize_body` tests against a live streaming HTTP server with chunked transfer encoding (`Transfer-Encoding: chunked`), verifying that `fetch_secure_content()` raises `PayloadTooLargeError` while streaming without buffering the full response into RAM.
3. **Model Candidate Training & Evaluation**:
   - `test_cti_phase5.py` fits real `RandomForestClassifier` models directly on the 268,215-row PaySim dataset. The 300+ second execution time is driven by true Scikit-Learn model training and evaluation rather than mock stubs.
4. **Mocked Behavior Identified**:
   - `test_05_response_size_limit_enforcement` in `test_cti_phase2.py` mocks `_PinnedHTTPConnection` headers to simulate a 10 MB payload header. This mock tests the early `Content-Length` header check, which complements the live chunked streaming test in `test_critical_remediations.py`.

---

## 5. Deployment Environment Suitability

| Environment | Suitability | Conditions & Prerequisites |
| :--- | :--- | :--- |
| **Local Development** | **SUITABLE** | Validated. All local databases, ML pipelines, and mock-free modules function immediately. |
| **Controlled Staging / Pilot** | **SUITABLE** | Validated. CTI collection, normalization, deduplication, and matching operate safely without corrupting data or risking SSRF. |
| **Unrestricted Production** | **CONDITIONALLY SUITABLE** | Requires: (1) Provisioning genuine API keys for OTX/AbuseIPDB, (2) Generating a timestamped production transaction log before activating candidate models, and (3) Mounting valid TLS certificates for external traffic. |
