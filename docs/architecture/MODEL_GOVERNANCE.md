# Machine Learning Model Governance & Registry Protocol

This document details dataset provenance, evaluation, approval, deployment, and rollback governance implemented in `upi-fraud-guard-v3`.

## 1. Dataset Provenance & Integrity

- **Training Corpus**: [`data/transactions_dataset.csv`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-v3/data/transactions_dataset.csv) (268,215 PaySim-derived rows with ground-truth binary fraud targets).
- **Schema Alignment**: Features are strictly mapped to the live transaction inference schema:
  - `amount`: Transaction amount in INR
  - `is_new_recipient`: Binary flag indicating unfamiliar payee
  - `payments_last_hour`: Frequency of outgoing transfers in recent window
  - `hour_of_day`: Circadian transaction hour
- **Partitioning**: Grouped split using `GroupShuffleSplit` (75% train, 25% test) hashed across feature tuples to prevent data leakage across train/test splits.
- **Limitation & Transparency**: The bundled processed dataset lacks authoritative granular timestamps. Therefore, temporal cross-validation is not possible on this specific artifact. This constraint is explicitly flagged in training metadata (`"temporal_evaluation": False, "deployment_eligible": False`).

## 2. Evaluation & Registry Workflow

1. **Training & Metrics**: Supported algorithms include `RandomForest`, `GradientBoosting`, and `LogisticRegression`. Candidates are evaluated for:
   - Precision & Recall
   - F1-Score
   - ROC-AUC & PR-AUC
   - False Positive Rate (FPR) & False Negative Rate (FNR)
   - Confusion Matrix (`tn`, `fp`, `fn`, `tp`)
2. **Artifact Serialization**: Candidate models are saved to `models/candidates/MODEL-TRANSACTION-{version}.joblib` along with their SHA-256 checksum.
3. **Registry Record**: Metadata is persisted in SQLite table `cti_model_registry` with initial status `Pending Approval`.
4. **Approval**: An analyst or administrator reviews metrics and triggers `/api/intelligence/models/{id}/approve`, transitioning status to `Approved`.
5. **Deployment Gate**:
   - To deploy, `/api/intelligence/models/{id}/deploy` checks that:
     1. Status is `Approved`.
     2. Candidate artifact exists and matches its recorded SHA-256 checksum.
     3. Feature schema matches runtime `FEATURE_NAMES`.
     4. Candidate has `"temporal_evaluation": True` and `"deployment_eligible": True`.
   - **Fail-Closed Policy**: Because `transactions_dataset.csv` lacks temporal validation, candidate models are refused production deployment (`Refusing model deployment: candidate lacks eligible temporal evaluation`), preventing unverified models from replacing the production model.
6. **Active Pointer & Runtime Hot-Swapping**:
   - When a valid model is activated, `transaction_module/analyzer.py` atomically updates `models/active_transaction_model.json` and loads the validated model into memory without server restarts.
7. **Rollback & Audit Trail**:
   - Every deployment and rollback writes immutable audit records to `cti_model_deployments` and `cti_model_audit`.
   - Rollback restores the exact previous artifact recorded in `previous_artifact` and re-verifies its SHA-256 checksum.
