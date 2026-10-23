"""
Step 2: train the transaction-risk classifier -- "Transaction fraud
detection" was previously rule-based only ("not ML-trained yet").

WHAT THIS SCRIPT DOES (in plain terms):
Reads the bundled, preprocessed data/transactions_dataset.csv and trains
the transaction model from it. In this project archive that dataset has
268,213 rows (260,000 normal and 8,213 fraud labels) and is the processed
PaySim-derived training input. The original raw data/paysim.csv is not
required to train from the bundled processed file. It is needed only if
you want to regenerate that processed dataset from scratch.

The dataset has an imbalanced fraud class, so this script compares three
ways of handling it instead of training naively:

  1. Baseline -- no imbalance handling.
  2. class_weight="balanced" -- makes each anomalous example count for
     more during training, proportional to how rare it is.
  3. SMOTE oversampling -- synthesizes extra anomalous training rows by
     interpolating between existing ones, balancing the training set
     itself before the model ever sees it.

All three get evaluated so the difference shows up in the printed
output -- useful evidence for the report/viva. The class_weight model
is what actually gets shipped (cheap, no synthetic rows needed, easy to
retrain as new labeled data comes in -- relevant to "adaptive learning").

The shipped model uses the class_weight='balanced' Random Forest. The
separately packaged IEEE-CIS artifact is for research evaluation and is
not loaded by the live API.

Run it with:  python 2_train_model.py
"""

import json
import sys
from pathlib import Path

import joblib
import pandas as pd
from imblearn.over_sampling import SMOTE
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR / "transaction_module"))
from transaction_features import extract_features, FEATURE_NAMES  # noqa: E402

DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
MODELS_DIR.mkdir(exist_ok=True)

df = pd.read_csv(DATA_DIR / "transactions_dataset.csv")
feature_rows = df.apply(
    lambda r: extract_features(r["amount"], r["is_new_recipient"], r["payments_last_hour"], r["hour_of_day"]),
    axis=1,
).apply(pd.Series)
X = feature_rows[FEATURE_NAMES]
y = df["target"]

print(f"Dataset anomaly rate: {y.mean() * 100:.2f}% ({y.sum()} of {len(y)})\n")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)


def evaluate(name, model):
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]
    print(f"--- {name} ---")
    print(classification_report(y_test, y_pred, target_names=["normal", "anomalous"], zero_division=0))
    print(f"ROC-AUC: {roc_auc_score(y_test, y_proba):.4f}\n")
    return y_pred, y_proba


print("=" * 60 + "\nComparing class-imbalance handling strategies\n" + "=" * 60 + "\n")

baseline = RandomForestClassifier(n_estimators=200, max_depth=8, random_state=42, n_jobs=1)
baseline.fit(X_train, y_train)
evaluate("Baseline (no imbalance handling)", baseline)

weighted = RandomForestClassifier(n_estimators=200, max_depth=8, class_weight="balanced", random_state=42, n_jobs=1)
weighted.fit(X_train, y_train)
y_pred_w, y_proba_w = evaluate("class_weight='balanced'", weighted)

smote = SMOTE(random_state=42)
X_train_sm, y_train_sm = smote.fit_resample(X_train, y_train)
print(f"After SMOTE: {len(y_train_sm)} rows, {y_train_sm.mean() * 100:.1f}% anomalous\n")
smote_model = RandomForestClassifier(n_estimators=200, max_depth=8, random_state=42, n_jobs=1)
smote_model.fit(X_train_sm, y_train_sm)
evaluate("SMOTE oversampling", smote_model)

# Ship the class_weight='balanced' model -- cheapest to keep retraining
# as new labeled data comes in, without needing a synthetic-sampling
# ratio to be re-tuned each time (the report's "adaptive learning" half
# of objective #7).
model = weighted
importances = pd.Series(model.feature_importances_, index=FEATURE_NAMES).sort_values(ascending=False)
print("=== Feature importance of the shipped model ===")
print(importances.to_string())

joblib.dump(model, MODELS_DIR / "transaction_model.joblib")
metrics = {
    "model": "Behavioural features + Random Forest (class_weight='balanced')",
    "test_samples": int(len(y_test)),
    "precision": round(float(precision_score(y_test, y_pred_w)), 4),
    "recall": round(float(recall_score(y_test, y_pred_w)), 4),
    "f1_score": round(float(f1_score(y_test, y_pred_w)), 4),
    "roc_auc": round(float(roc_auc_score(y_test, y_proba_w)), 4),
}
(MODELS_DIR / "transaction_metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
print("\nSaved model to models/transaction_model.joblib")
print("Saved evaluation metrics to models/transaction_metrics.json")
