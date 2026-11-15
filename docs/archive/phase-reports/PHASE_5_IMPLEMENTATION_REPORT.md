# PHASE 5 IMPLEMENTATION REPORT — CONTINUOUS MACHINE LEARNING PIPELINE & MODEL REGISTRY

**Module:** Quality-Controlled Continuous ML Pipeline & Model Registry  
**Version:** 3.0.0-Enterprise-CTI  
**Completion Date:** March 2026  
**Status:** COMPLETE & TESTED (Phase 5 Continuous Learning Layer)  

---

## 1. Files Created and Modified

```
BACKEND (upi-fraud-guard-v3/)
├── cti_ml_pipeline.py     [CREATED]  Dataset preparer, candidate evaluator, and Model Registry manager
├── test_cti_phase5.py      [CREATED]  Phase 5 integration test suite for dataset prep, training, registry, approval, deployment & rollback
└── cti_api.py             [MODIFIED] Added model registry REST API endpoints (/models, /train, /approve, /deploy, /rollback)
```

---

## 2. Training Architecture & Dataset Provenance

* **Quality-Controlled Dataset Preparation ([cti_ml_pipeline.py](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/cti_ml_pipeline.py))**:
  - **Strict Provenance Rule**: NEVER trains directly on raw unverified web content or unverified internet feeds!
  - Integrates verified malicious CTI indicators (`cti_indicators` where `verification_status == 'Verified Malicious'`) with curated benchmark datasets (`data/messages_clean.csv`, `data/transactions_dataset.csv`).
  - Separates verified malicious, verified benign, and unlabelled records.
  - Removes duplicate records, validates target labels, and enforces stratified/temporal train/test splitting (`70% train`, `30% test`).
  - Dataset Versioning: Automatically versions every prepared dataset (`v1.0.0`, `v1.1.0`, etc.).

---

## 3. Feature Engineering & Inference Schema Compatibility

Features are built to maintain 100% compatibility with live real-time inference schemas:
- **Message Classifier**: Word and character n-gram (1-3) TF-IDF features.
- **URL & Domain Classifier**: Lexical features (url length, dots, hyphens, digits, subdomains, IP address host, AT symbol, HTTPS, shortener, throwaway TLD).
- **Transaction Scorer**: Behavioral features (amount, recipient novelty, payment frequency, hour of day).

---

## 4. Evaluation Methodology & Metrics

Candidate models (Random Forest, Gradient Boosting, Logistic Regression) are evaluated on held-out test splits.

Metrics Computed:
- **Precision**: Proportion of true fraud alerts among total predicted fraud.
- **Recall**: Proportion of true fraud cases correctly detected.
- **F1-Score**: Harmonic mean of Precision and Recall.
- **ROC-AUC & PR-AUC**: Area under Receiver Operating Characteristic and Precision-Recall curves.
- **Confusion Matrix**: Full breakdown of True Negatives ($TN$), False Positives ($FP$), False Negatives ($FN$), and True Positives ($TP$).
- **False-Positive & False-Negative Rates**: Explicit tracking to minimize operational false alarms.

---

## 5. Model Registry & Controlled Approval Workflow

Candidate models are registered in the persistent SQLite database (`cti_model_registry` table):

```
[ Candidate Training Request ]
             |
             v
[ Candidate Evaluated & Artifact Saved to models/candidates/ ]
             |
             v
[ Model Registered: Status = 'Pending Approval', is_active = 0 ]
             |
             +---> Analyst / Admin Review Metrics (Precision, Recall, F1)
             |
             v
[ POST /api/intelligence/models/{id}/approve ]
             |
             v
[ Status = 'Approved' ]
             |
             v
[ POST /api/intelligence/models/{id}/deploy ]
             |
             v
[ Active Model Swapped: Status = 'Deployed', is_active = 1 ]
             |
             +---> Optional: Rollback via POST /api/intelligence/models/{id}/rollback
```

* **No Automatic Deployment**: Candidates are NEVER deployed automatically upon training. Deployment requires explicit administrator approval via `/deploy`.
* **Rollback Support**: `/rollback` deactivates the current model and restores the previous active production model version.

---

## 6. API Endpoint Documentation ([cti_api.py](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/cti_api.py))

| Endpoint | Method | RBAC Permission | Description |
| :--- | :--- | :--- | :--- |
| `/api/intelligence/models` | `GET` | All Roles | Lists registered models, active version, metrics, and approval status. |
| `/api/intelligence/models/evaluations` | `GET` | All Roles | Retrieves evaluation comparison metrics for candidate and active models. |
| `/api/intelligence/models/monitoring` | `GET` | All Roles | Retrieves statistical data drift & latency monitoring reports. |
| `/api/intelligence/models/{model_id}` | `GET` | All Roles | Retrieves single model metadata, metrics, and artifact path. |
| `/api/intelligence/models/train` | `POST` | `super_admin`, `fraud_analyst` | Triggers candidate model training on validated datasets. |
| `/api/intelligence/models/{model_id}/approve` | `POST` | `super_admin` | Administrator endpoint to approve candidate model. |
| `/api/intelligence/models/{model_id}/deploy` | `POST` | `super_admin` | Administrator endpoint to deploy approved candidate to active production. |
| `/api/intelligence/models/{model_id}/rollback` | `POST` | `super_admin` | Administrator endpoint to rollback active model to previous version. |

---

## 7. Unit & Integration Test Results

Ran `python test_cti_phase5.py`:
```
Ran 5 tests in 0.906s
STATUS: OK (100% Pass Rate)
```
- `test_01_dataset_preparation`: **PASSED**
- `test_02_candidate_model_training`: **PASSED**
- `test_03_model_approval_and_deployment_workflow`: **PASSED**
- `test_04_model_version_rollback`: **PASSED**
- `test_05_model_registry_api`: **PASSED**

---

## 8. Scope Restrictions Checklist

* Unverified threat intelligence was **never used for model training**.
* Automatic candidate model deployment was **not performed** (requires manual approval).
* Existing production model artifacts were **preserved unchanged**.
* Existing detection features, Android client, and frontend were **preserved unchanged**.
* Phase 6 was **not started**.

---

*Phase 5 is completed and verified. In accordance with your instructions, Phase 6 has not been started. Please provide your approval to proceed to Phase 6.*
