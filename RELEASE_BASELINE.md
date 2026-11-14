# Release Baseline Document — UPI Fraud Guard Enterprise v2.6.0-RC1

**Baseline Date:** 2026-11-10  
**Version:** `2.6.0-Enterprise` (`v2.6.0-RC1`)  
**Workspace Root:** `UPI-Fraud-Guard-Multilingual-Improved`  
**Primary Subprojects:**
- Backend: `upi-fraud-guard-v3`
- Mobile: `upi-fraud-guard-android`

---

## 1. Environment & Runtime Baseline

- **Python Runtime:** Python 3.13.14 (Compatible with Python 3.10+)
- **OS Platform:** Windows / Linux (Posix & NT verified)
- **Key Python Dependencies:**
  - `fastapi >= 0.110`
  - `uvicorn[standard] >= 0.27`
  - `scikit-learn == 1.7.2` (exact version pin required for model artifact binary compatibility)
  - `pandas >= 2.0`
  - `joblib >= 1.3`
  - `shap >= 0.45`
  - `imbalanced-learn >= 0.12`
  - `Pillow >= 10.0`
  - `pyzbar >= 0.1.9`
  - `python-multipart >= 0.0.9`

---

## 2. Active Model Artifacts & Provenance

| Model File | Checksum (SHA-256) | Training Source | Features |
| :--- | :--- | :--- | :--- |
| `models/transaction_model.joblib` | Verified | `data/transactions_dataset.csv` (268,215 rows) | `amount`, `is_new_recipient`, `payments_last_hour`, `is_night` |
| `models/nlp_model.joblib` | Verified | `data/messages_clean.csv` + additions | TF-IDF (1,500 Devanagari/Latin n-grams) |
| `models/nlp_vectorizer.joblib` | Verified | `data/messages_clean.csv` | Scikit-Learn TfidfVectorizer |
| `models/url_model.joblib` | Verified | `data/real_url_lists/` | Lexical URL features (13 engineered signals) |

*Active Pointer Configuration:* `models/active_transaction_model.json` tracks the active model path and expected SHA-256 digest.

---

## 3. Database Schema & State

- **Database File:** `data/risk_checks.db`
- **Tables Present & Active:**
  1. `risk_checks`: Historical pre-transaction checks, verdicts, reasons, SHAP values, and user IDs.
  2. `investigations`: Fraud case management, priority, assignee, notes, and status lifecycle.
  3. `cti_sources`: Registered feed adapters, sync timestamps, checkpoints, and health states.
  4. `cti_indicators`: Normalized indicators with verification status, confidence, expiry, and quarantine flags.
  5. `cti_indicator_quarantine`: False-positive isolation audit log.
  6. `cti_collection_logs`: Historical audit logs for autonomous and manual collection runs.
  7. `cti_fraud_patterns`: Categorized scam types (KYC, OTP harvesting, collect-request, QR fraud).
  8. `cti_indicator_reviews`: Analyst review decision history with previous/new status.
  9. `cti_model_registry`: Registered candidate models, algorithms, dataset versions, and evaluation metrics.
  10. `cti_model_audit`: Audit trail of model training, approval, deployment, and rollback events.
  11. `cti_model_deployments`: Immutable record of active model hot-swaps and previous artifact pointers.

---

## 4. Test Suite Execution Command & Passing Baseline

```powershell
python -m unittest test_critical_remediations.py test_cti_phase2.py test_cti_phase3.py test_cti_phase4.py test_cti_phase5.py test_cti_phase6.py test_suite.py
```

- **Total Tests:** 48
- **Passing:** 48 (100%)
- **Failing:** 0
- **Errors:** 0
- **Duration:** 314.887 seconds
- **Test Integrity:** Real RandomForest model training and evaluation across 268k rows; live socket connections and chunked streaming byte limits exercised.
