# UPI Fraud Guard Phases 2–5 Recovery and Verification Audit

**Audit scope:** Read-only review of the recovered workspace on 2026-11-10. No production source, database row, or production model artifact was changed. Existing tests ran against a disposable copy.

## Executive assessment

The recovered `upi-fraud-guard-v3` workspace contains a working FastAPI/SQLite application, ten registered CTI source connectors, CTI API endpoints, matching hooks in URL/QR and transaction analysis, a browser dashboard, model registry code, and packaged model/data artifacts. The Phase 2–5 test suites can pass when the risk-check schema is initialized first in a test copy.

The implementation is **not ready to treat as an autonomous, trustworthy CTI or safe model-deployment platform**. Several source adapters substitute hardcoded demonstration IOCs on errors or instead of querying their advertised feeds; those records can be labeled verified and logged as successful. The extraction and confidence-normalization modules are not connected to the collection path. The Phase 5 registry trains on generated random features/labels and deploys only registry flags; it never changes the models loaded by risk scoring. Audit coverage and deployment rollback are incomplete. The existing static dashboard exposes administrative controls without authentication integration, and renders many backend fields as HTML without escaping.

## Workspace and files inspected

Workspace: `UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3`.

Inspected the project README, requirements, startup script, frontend markup/script/styles, API startup/routes/security, CTI modules, model pipeline and monitor, CTI/database code, the dual-feed and scoring integration, existing phase tests, and persisted SQLite table inventory/counts.

CTI modules reviewed (the implementation has nine modules in this group):

- `cti_api.py`
- `cti_collector.py`
- `cti_connectors.py`
- `cti_database.py`
- `cti_extraction.py`
- `cti_matcher.py`
- `cti_ml_pipeline.py`
- `cti_normalization.py`
- `cti_security.py`

Also inspected: `api/main.py`, `api/security.py`, `run_api.py`, `dual_feed.py`, `risk_fusion.py`, `model_monitor.py`, `evaluate_models.py`, `multilingual_message_rules.py`, `url_qr_module/analyzer.py`, `url_qr_module/upi_qr.py`, `url_qr_module/qr_decoder.py`, `transaction_module/analyzer.py`, `transaction_module/transaction_features.py`, NLP training/evaluation scripts, `frontend/index.html`, `frontend/script.js`, `frontend/style.css`, `requirements.txt`, and `test_cti_phase2.py` through `test_cti_phase6.py` plus `test_suite.py`.

## Phase 2 — CTI infrastructure, connectors, scheduler, security

**Status: Partially implemented; collection is not reliably live or trustworthy.**

- Imports resolve in the available environment; all related test modules imported and ran. FastAPI starts the singleton worker from `api.main.startup` and calls shutdown from `api.main.shutdown`. `run_api.py` validates security configuration and refuses non-loopback binding without configured API users and both TLS files.
- The worker begins a collection round immediately, then sleeps for `CTI_COLLECTION_INTERVAL_MINUTES` (default 30). It runs synchronous connector calls sequentially in an executor. The shutdown path cancels the async task and releases a lock file. However, file locking is a check-then-write, not an atomic OS lock; simultaneous starts can both acquire it. On lock-file I/O failure it deliberately proceeds without a lock. Shutdown cancellation cannot stop an already-running executor thread, so it can release the lock while connector work is still underway. No exponential backoff is implemented despite the collector docstring claiming it.
- Ten source adapters register at import. Configured live-feed URLs are CERT-In RSS, PhishTank JSON, URLhaus recent-URLs API, OpenPhish text, CISA KEV JSON, AbuseIPDB blacklist API, and AlienVault OTX subscribed pulses. The AbuseIPDB and OTX requests require `ABUSEIPDB_API_KEY` and `OTX_API_KEY`, respectively.
- NPCI, RBI, and MITRE adapters return fixed static entries instead of fetching the configured URLs. On errors, CERT-In, PhishTank, URLhaus, OpenPhish, and CISA return fixed sample/fallback indicators. Optional-key connectors also return a fixed sample when the key is absent. These fallbacks are subsequently inserted and counted as normal successful collection. Several such sample values are clearly synthetic or malformed for their declared type (e.g. ATT&CK pseudo-domain values and CISA CVE IDs stored as `hash`). Fallback error status is therefore hidden and dashboard counts can describe sample data as live collection.
- `cti_security.py` blocks many private IP ranges, validates redirects, and sets timeout/size limits. Material flaws remain: `response.read()` reads the complete body before enforcing the size limit, so the claimed 5 MiB cap does not bound memory use; DNS is checked separately from HTTPX’s later connection resolution, leaving a DNS-rebinding/TOCTOU gap; and caller-provided headers (including API keys) are reused after redirects to a different host, creating credential disclosure risk.
- The collector result/log does not expose failed requests or rate-limit state reliably. Source schema has one `last_sync` timestamp, not distinct last-attempt/last-success timestamps. `update_source_sync` is not called on every failure path in a way that preserves that distinction.

## Phase 3 — extraction, normalization, confidence, persistence, CTI APIs

**Status: Data structures and endpoints exist; principal processing steps are not connected end-to-end.**

- `cti_extraction.py` defines regex extraction for URL/domain/IP/hash/email/VPA and keyword groups for eight scam categories. The source connectors do not call it, and `cti_collector.py` does not call it. Collection expects already-structured records, so advisory/feed prose does not produce extracted indicators or patterns.
- `cti_normalization.py` provides canonicalization, syntax validation, allowlist checks, expiry calculation, and confidence/status mapping. These functions are not called from collection or `cti_database.add_indicator`; collector-provided raw values/status/confidence are stored. `source_count` corroboration is not populated by collection. Duplicate insertions update only `last_seen` and maximum confidence; they do not add source attribution/evidence or update status.
- SQLite tables present in the actual database: `risk_checks`, `investigations`, `cti_sources`, `cti_indicators`, `cti_collection_logs`, `cti_fraud_patterns`, `cti_indicator_reviews`, and `cti_model_registry`. Read-only counts at audit time: 10 sources, 97 indicators, 27 collection logs, 7 indicator reviews, and 17 registry rows. These counts do not establish that the indicators are valid or live; the connector fallback behavior above makes provenance uncertain.
- CTI API includes status, sources, collection trigger, paginated indicators, indicator details, generated fraud-pattern categories, collection logs, reviews, model registry/evaluation/monitoring, training, approval, deployment, and rollback routes.
- Missing CTI functionality includes filtering by threat category/confidence/first-seen/expiry; count-safe database pagination (routes load capped result sets into memory and slice them); an indicator review-history read route; date/event-filterable paginated audit log; real emerging-pattern records/supporting indicators; per-source failed-request/rate-limit/attempt fields; and several overview metrics (expired, successful/failed jobs, next scheduled run, synchronization timestamp). Status totals are based on a limited query, not SQL counts.
- `/fraud-patterns` synthesizes descriptions from static keyword constants; it does not return persisted or intelligence-supported emerging patterns. `cti_fraud_patterns` exists but has no populated CRUD workflow in the reviewed modules.

## Phase 4 — CTI matching and risk fusion

**Status: Basic URL/domain/VPA matching and risk fusion are wired; matching policy has gaps.**

- `url_qr_module/analyzer.py` calls the CTI matcher for URL/domain and parsed QR payee VPA. `transaction_module/analyzer.py` calls it for recipient VPA. `risk_fusion.py` incorporates CTI evidence. The message path does not call `cti_matcher.match_message_patterns`; multilingual message rules are a separate keyword/model path.
- The matcher claims verified-only behavior but includes any non-expired indicator with confidence ≥80, even when its verification status is not Verified Malicious. The database query clamps limits to 1,000 while the matcher requests 5,000, so older indicators beyond the first 1,000 collected records are not considered. The cache reduces query frequency but is only invalidated by explicit calls; API reviews do not invalidate it, leaving stale classifications for up to the 30-second TTL.
- The Phase 4 tests cover sample URL/VPA matches, expiration, fusion, and DB failure fallback. They do not exercise unverified high-confidence handling, cache invalidation after review, real connector provenance, or complete corpus matching.

## Phase 5 — training, provenance, evaluation, registry, approval/deployment

**Status: Registry workflow code exists, but it is not a valid production model-training/deployment pipeline.**

- Existing NLP, URL, and transaction artifacts and evaluation JSON files are present. README/data notes describe bundled English/Hindi/Hinglish and translated Marathi corpora and PaySim-derived transaction data. These are distinct from the CTI Phase 5 candidate pipeline.
- `cti_ml_pipeline.DatasetPreparer` ignores those datasets and the verified indicators as training features. It creates 1,500 seeded random feature vectors and synthetic labels. The verified-malicious count is calculated by adding the number of database IOCs to synthetic positive labels, which is not a sample count from the training matrix. The requested `dataset_version` is metadata only.
- The evaluator computes common classification metrics and writes a candidate `.joblib` to `models/candidates`, then stores metadata in SQLite. This trains a synthetic demonstration model, not a model learned from the project’s fraud data.
- Approval is a status update with no recorded approver/time/evidence. Deployment toggles registry `is_active` flags only. `api.main` loads the existing fixed `nlp_model.joblib`/vectorizer at module import; registry deploy/rollback never loads or routes predictions to candidate artifacts. Thus a “deployed” candidate does not change fraud scoring.
- Rollback selects the most recently trained different registry row, not a recorded previous deployed model. It can select an unapproved candidate, and succeeds even when no prior deployment exists. There is no deployment history table, model artifact checksum/signature verification, model compatibility check, or audit trail for approvals/deployments/rollbacks.
- `/models/evaluations` is a listing of registry rows rather than an independent evaluation-history endpoint. Model monitoring loads static JSON snapshots and calculates a simple recent-mean difference against a fixed 0.15 baseline; no labelled prediction outcome history, model evaluation history, or robust drift analysis is implemented.

## Authentication, RBAC, audit, frontend

**Status: API token gating and endpoint role dependencies exist; dashboard integration and audit coverage are deficient.**

- Tokens are configured by `UPI_FRAUD_GUARD_API_USERS`, hashed with SHA-256, and compared with constant-time digest comparison. The local-development identity is implicitly `super_admin`; unknown token user IDs default to `fraud_analyst`. There is no configuration-backed role mapping for arbitrary token IDs. The README documents TLS and token environment configuration; optional external CTI secrets are `ABUSEIPDB_API_KEY` and `OTX_API_KEY`. No deployment configuration/secrets were verified in this audit.
- CTI write actions generally use role dependencies: collection/review/training allow super-admin or fraud analyst; model approve/deploy/rollback require super-admin. However, reads are accessible to any authenticated user. Investigation updates have no role dependency. Tests run with default local development identity, so they do not verify unauthorized requests or RBAC boundaries.
- Browser frontend uses unauthenticated `fetch()` calls and has no token/session setup or role-aware visibility. It renders admin actions (collect, train, review, approve, deploy, rollback, add threat) for everyone. API dependencies may reject them when authentication is configured, but the UI provides no supported authenticated route or role response handling.
- External/backend values are interpolated into `innerHTML` templates across CTI, feed, mule, investigation, and model views. An `escapeHtml` helper exists but is used only in a subset of indicator rendering; other values such as pattern keywords, source names, descriptions, model fields, logs, and case text are not consistently escaped. This creates stored/reflected DOM XSS exposure if untrusted intelligence text reaches the API.
- The audit trail is fragmented: collection logs and indicator-review rows exist, but no review-history API or unified administrative/model lifecycle event log exists. Model approval/deployment/rollback changes are not audit-logged. No date/event filters are provided for collection logs.
- Phase 6 dashboard is present as a partial screen. It includes sources, indicators, keyword categories, models, and collection logs, but omits several requested fields/visualizations and has no loading/error UX beyond initial “Loading” strings and console logs. Requests parse JSON without checking HTTP status. Metrics include a hardcoded “10” in HTML. No pagination UI; filter coverage is only text, indicator type and verification status. Sensitive values are displayed raw. Pattern suggestions are not distinguished from verified findings. The UI does not show model confusion matrix, PR-AUC/FPR, prediction history, or evaluation history.

## Missing files, dependencies, configuration, and endpoints

- No import failures were observed while running the test modules; installed dependencies in this environment were sufficient. `requirements.txt` lists the main runtime/model dependencies. The test run emitted a Starlette warning that using `httpx` with `starlette.testclient` is deprecated; no compatible test dependency pin is listed.
- Required deployment values for non-loopback operation: per-user `UPI_FRAUD_GUARD_API_USERS`, `UPI_FRAUD_GUARD_TLS_CERT`, `UPI_FRAUD_GUARD_TLS_KEY`; optional connector keys above; optional scheduler interval `CTI_COLLECTION_INTERVAL_MINUTES`. No deployment-specific environment file was found in the inspected tree.
- Missing endpoints include indicator review history, audit event filtering across admin/model actions, and complete collection/model history needed by the Phase 6 dashboard requirements.
- Existing route names are implemented in `cti_api.py`; their existence should not be read as evidence that each underlying feature is complete or grounded in live data.

## Tests and results

Tests were run from a disposable copy of the Python source, frontend, and model artifacts. This avoided writing to the original `data/risk_checks.db` or original `models/candidates`.

Commands used in the disposable copy:

1. `python -c "from api.main import initialise_db; initialise_db()"` (initialize the copy’s risk-check schema because the test files instantiate `TestClient` without entering its lifespan context).
2. `python -m unittest discover -v`

**Result:** 40 tests ran in 7.359 seconds; all passed. This includes Phase 2–5 CTI suites, the Phase 6 dashboard API suite already present in the repository, and `test_suite.py`. The test run emitted a Starlette/httpx deprecation warning and expected diagnostic log lines for mocked database failure and rejected premature deployment.

A first run without the explicit disposable-copy DB initialization ran 40 tests and failed 3 general-suite cases with `sqlite3.OperationalError: no such table: risk_checks`; the cause is that the tests do not invoke FastAPI lifespan/startup. After initializing the clone, the same suites passed. Passing tests mainly establish the narrow behavior asserted by the current tests; they do not validate live source authenticity, production startup under real configuration, unauthorized roles, XSS, body-size limits, real training-data provenance, or actual model activation.

## Critical security and integrity issues

1. **High — CTI credential disclosure on redirects:** `fetch_secure_content` reuses API-key headers on cross-host redirect targets.
2. **High — response-size guard is ineffective against memory exhaustion:** the body is fully read before checking its size.
3. **High — DNS rebinding/TOCTOU exposure:** the validator resolves and checks a host, then HTTPX resolves/connects independently.
4. **High — dashboard DOM XSS:** multiple untrusted fields are inserted into `innerHTML` without complete escaping.
5. **High — false threat intelligence:** static fallback/demo values are persisted and labeled verified/successful after live fetch errors or where no feed call exists; these can influence risk matching.
6. **High — misleading model deployment:** registry deployment/rollback state does not affect the actual loaded inference models; Phase 5 candidates use synthetic data.
7. **Medium — lock is not mutual exclusion:** check/write race and permissive failure fallback can start multiple collection workers.
8. **Medium — authorization/UI mismatch:** admin controls are always shown, browser requests cannot attach configured bearer tokens, and existing tests do not exercise denied roles.
9. **Medium — audit gaps:** model lifecycle and administrative operations are not recorded; review history has no read API.

## Phase 6 readiness

**Not ready for Phase 6 completion or production CTI operations.** A dashboard is already partially present, but its data can be synthetic/stale, it cannot authenticate configured users, and it lacks required APIs/fields and safety handling. Before relying on it, source provenance/fallback behavior, request security, extraction/normalization integration, database query completeness, model training/deployment semantics, auditability, and frontend output encoding need remediation. The previous Phase 6 implementation report in the nested Android checkout describes a different workspace and is not evidence about this recovered project.

## Files changed

Only this audit report was created. No production source, database records, or model artifacts were modified. Phase 6 and Phase 7 implementation work was not started.
