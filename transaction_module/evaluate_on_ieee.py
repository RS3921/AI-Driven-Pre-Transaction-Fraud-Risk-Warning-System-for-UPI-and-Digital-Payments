"""
Cross-dataset validation: test the PaySim-trained transaction model
against a SECOND, completely independent real fraud dataset -- IEEE-CIS
(Kaggle: ieee-fraud-detection, 590,540 real e-commerce transactions,
3.5% fraud rate).

IMPORTANT, HONEST CAVEAT -- READ BEFORE QUOTING RESULTS IN THE REPORT:
IEEE-CIS is CARD/E-COMMERCE fraud data (someone buying something online
with a card), not peer-to-peer money-transfer fraud like PaySim or real
UPI payments. There is no real "recipient" in a card transaction the
way there is in a UPI/PaySim transfer -- a shopper doesn't "pay" a
person, they pay a merchant. So the 4 features this project's
transaction model uses are APPROXIMATED here, not natively present:

  - amount               -> IEEE-CIS's TransactionAmt directly (same concept: money moved)
  - hour_of_day           -> derived from TransactionDT (seconds-since-reference) via (DT // 3600) % 24
  - is_new_recipient      -> APPROXIMATED as "is this the first transaction from this card1
                              (card identifier) in the dataset" -- a proxy for an unfamiliar
                              payment instrument, not a genuinely new recipient
  - payments_last_hour    -> count of other transactions from the same card1 in the same
                              derived hour bucket

This script does TWO things, both useful, both honestly reported:

  1. Runs the EXISTING PaySim-trained model (no retraining) on IEEE-CIS
     data -- a true test of whether patterns learned from one real
     fraud dataset transfer to a completely different real fraud
     dataset. Don't expect this to score as well as testing on PaySim's
     own held-out data -- a meaningful drop here is EXPECTED and
     informative, not a bug.
  2. Trains a SEPARATE, fresh model on IEEE-CIS alone (same
     architecture, same imbalance-handling approach as
     transaction_module/2_train_model.py) so you have a fair, properly-
     trained-on-its-own-data comparison point.

This is meant to produce evidence for a "we validated across two
independent real-world datasets" discussion in the report -- with the
domain-mismatch caveat above stated plainly, not glossed over.

Run it with:  python evaluate_on_ieee.py
(Needs data/ieee_train_transaction.csv -- the real IEEE-CIS training
file from https://www.kaggle.com/c/ieee-fraud-detection/data -- present
locally. Not shipped in the project zip due to its size (~650MB).)
"""

import sys
import json
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
IEEE_PATH = DATA_DIR / "ieee_train_transaction.csv"

if not IEEE_PATH.exists():
    print(f"Could not find {IEEE_PATH}")
    print("Download train_transaction.csv from https://www.kaggle.com/c/ieee-fraud-detection/data")
    print("and place it at data/ieee_train_transaction.csv, then rerun this script.")
    sys.exit(1)

print("Loading IEEE-CIS data (this is a large file, may take a minute)...")
raw = pd.read_csv(IEEE_PATH, usecols=["isFraud", "TransactionAmt", "TransactionDT", "card1"])
print(f"Loaded {len(raw):,} real e-commerce transactions "
      f"({raw['isFraud'].sum():,} fraud, {raw['isFraud'].mean() * 100:.2f}% -- IEEE-CIS's real-world fraud rate)")

# --- Derive this project's 4 features from IEEE-CIS's columns (see the caveat above) ---
raw["hour_of_day"] = (raw["TransactionDT"] // 3600) % 24
raw = raw.sort_values(["card1", "TransactionDT"]).reset_index(drop=True)
card_seen_count = raw.groupby("card1").cumcount()
raw["is_new_recipient"] = (card_seen_count == 0).astype(int)
hour_bucket = raw["TransactionDT"] // 3600
raw["payments_last_hour"] = raw.groupby(["card1", hour_bucket])["card1"].transform("count") - 1

feature_rows = raw.apply(
    lambda r: extract_features(r["TransactionAmt"], r["is_new_recipient"], r["payments_last_hour"], r["hour_of_day"]),
    axis=1,
).apply(pd.Series)
X = feature_rows[FEATURE_NAMES]
y = raw["isFraud"]

print(f"\nDerived feature summary:\n{X.describe().to_string()}\n")

# === PART 1: test the EXISTING PaySim-trained model with no retraining ===
print("=" * 70)
print("PART 1: Cross-domain test -- PaySim-trained model, unmodified, on IEEE-CIS")
print("=" * 70)
paysim_model = joblib.load(MODELS_DIR / "transaction_model.joblib")
y_proba_cross = paysim_model.predict_proba(X)[:, 1]
y_pred_cross = paysim_model.predict(X)
print(classification_report(y, y_pred_cross, target_names=["normal", "anomalous"], zero_division=0))
cross_auc = roc_auc_score(y, y_proba_cross)
print(f"ROC-AUC (PaySim model on IEEE-CIS data): {cross_auc:.4f}")
print("(A drop compared to PaySim's own ~0.84 held-out score is EXPECTED -- this measures")
print(" whether fraud patterns learned on one real dataset transfer to a different one.)\n")

# === PART 2: train a fresh model on IEEE-CIS alone, for a fair same-dataset comparison ===
print("=" * 70)
print("PART 2: Training a fresh model on IEEE-CIS alone (same approach as PaySim model)")
print("=" * 70)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

ieee_model = RandomForestClassifier(n_estimators=200, max_depth=8, class_weight="balanced", random_state=42, n_jobs=-1)
ieee_model.fit(X_train, y_train)
y_pred_ieee = ieee_model.predict(X_test)
y_proba_ieee = ieee_model.predict_proba(X_test)[:, 1]
print(classification_report(y_test, y_pred_ieee, target_names=["normal", "anomalous"], zero_division=0))
ieee_auc = roc_auc_score(y_test, y_proba_ieee)
print(f"ROC-AUC (fresh model trained on IEEE-CIS): {ieee_auc:.4f}")

importances = pd.Series(ieee_model.feature_importances_, index=FEATURE_NAMES).sort_values(ascending=False)
print("\n=== Feature importance (IEEE-CIS-trained model) ===")
print(importances.to_string())

joblib.dump(ieee_model, MODELS_DIR / "ieee_transaction_model.joblib")

summary = {
    "paysim_model_on_ieee_data": {
        "roc_auc": round(float(cross_auc), 4),
        "precision": round(float(precision_score(y, y_pred_cross, zero_division=0)), 4),
        "recall": round(float(recall_score(y, y_pred_cross, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y, y_pred_cross, zero_division=0)), 4),
        "note": "Cross-domain test: PaySim-trained model evaluated with no retraining.",
    },
    "fresh_model_trained_on_ieee": {
        "roc_auc": round(float(ieee_auc), 4),
        "precision": round(float(precision_score(y_test, y_pred_ieee, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, y_pred_ieee, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y_test, y_pred_ieee, zero_division=0)), 4),
        "note": "Separately trained and evaluated on IEEE-CIS's own held-out split.",
    },
    "domain_mismatch_caveat": (
        "IEEE-CIS is card/e-commerce fraud data, not peer-to-peer transfer fraud like "
        "PaySim/UPI. 'is_new_recipient' and 'payments_last_hour' are approximated from "
        "card1 (card identifier), not a true recipient -- see this script's docstring."
    ),
}
(MODELS_DIR / "ieee_cross_validation_metrics.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
print("\nSaved cross-validation summary to models/ieee_cross_validation_metrics.json")
print("Saved the IEEE-CIS-only model to models/ieee_transaction_model.joblib (for reference; not used by the live API)")
