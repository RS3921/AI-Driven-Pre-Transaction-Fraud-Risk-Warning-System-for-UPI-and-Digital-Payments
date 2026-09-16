"""Transaction-risk scoring for the pre-payment demo.

Now model-backed: the score comes from a Random Forest classifier
trained on labeled transaction data with explicit class-imbalance
handling (see 1_generate_dataset.py / 2_train_model.py). The rule-based
checks below are KEPT and still run -- they no longer set the score,
but they generate the plain-language "reasons" shown to the user, same
approach as url_qr_module/analyzer.py. A real SHAP-based explanation of
THIS specific prediction is also computed (see shap_explainability.py)
and returned separately as "shap_explanation".
"""
from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

import joblib
import pandas as pd

from shap_explainability import explain_prediction

FEATURE_LABELS = {
    "amount": "Payment amount",
    "is_new_recipient": "Recipient is new",
    "payments_last_hour": "Number of payments in the last hour",
    "is_night": "Payment made late at night",
}

_MODULE_DIR = Path(__file__).resolve().parent
_MODELS_DIR = _MODULE_DIR.parent / "models"
sys.path.insert(0, str(_MODULE_DIR))
from transaction_features import extract_features, FEATURE_NAMES  # noqa: E402

try:
    _txn_model = joblib.load(_MODELS_DIR / "transaction_model.joblib")
except FileNotFoundError:
    _txn_model = None  # falls back to a rule-based score below until `python setup.py` is run


def analyse_transaction(amount: float | None, recipient: str | None, payments_last_hour: int | None, is_new_recipient: bool | None) -> dict:
    # NOTE: is_new_recipient is deliberately excluded from this check.
    # It comes from a checkbox on the frontend, which can only ever send
    # true or false -- never a genuine "not answered" state -- so
    # including it here meant this condition was NEVER true (the
    # transaction module always ran, even with every other field left
    # blank). With amount=None, the analyzer fell back to amount=0,
    # which is a value the model never saw in training (every real
    # transaction has a positive amount) -- an out-of-distribution
    # input that caused wildly incorrect scores (observed: 0.98, i.e.
    # near-maximum risk, for a completely empty transaction section).
    if amount is None and not recipient and payments_last_hour is None:
        return {"score": None, "reasons": [], "shap_explanation": []}

    amount = amount or 0
    hour_of_day = datetime.now().hour
    reasons: list[str] = []

    # --- Rule-based checks: kept as-is, now feed only the "reasons" ---
    if amount >= 50000:
        reasons.append("Payment amount is far above the normal demo threshold")
    elif amount >= 10000:
        reasons.append("Payment amount is high")
    elif amount >= 5000:
        reasons.append("Payment amount deserves confirmation")
    if is_new_recipient:
        reasons.append("Recipient is marked as new")
    if (payments_last_hour or 0) >= 6:
        reasons.append("Many payment attempts were made in the last hour")
    elif (payments_last_hour or 0) >= 3:
        reasons.append("Several payment attempts were made recently")
    if hour_of_day < 5 and amount >= 5000:
        reasons.append("High-value payment is being made at an unusual hour")
    if recipient and len(recipient.strip()) < 3:
        reasons.append("Recipient identifier is unusually short")

    # --- ML score: the trained model is the actual risk score now ---
    if _txn_model is not None:
        row = pd.DataFrame([extract_features(amount, is_new_recipient, payments_last_hour, hour_of_day)])[FEATURE_NAMES]
        score = float(_txn_model.predict_proba(row)[0][1])
        shap_explanation = explain_prediction("transaction_model.joblib", row, FEATURE_LABELS)
    else:
        score = min(0.98, 0.03 + 0.15 * len(reasons))  # fallback if model not yet trained
        shap_explanation = []

    if not reasons:
        reasons.append("No unusual transaction pattern was selected")
    return {"score": round(min(score, 0.98), 3), "reasons": reasons, "shap_explanation": shap_explanation}
