"""Transaction-risk scoring for the pre-payment demo.

ML-backed Random Forest + Rule-based checks + CTI VPA Threat Integration.
"""
from __future__ import annotations

import sys
import hashlib
import json
import logging
from datetime import datetime
from pathlib import Path

import joblib
import pandas as pd

from shap_explainability import explain_prediction
from cti_matcher import cti_matcher

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

_LOGGER = logging.getLogger("upi_fraud_guard.transaction_model")
_POINTER_PATH = _MODELS_DIR / "active_transaction_model.json"
_ACTIVE_MODEL_PATH = _MODELS_DIR / "transaction_model.joblib"


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_model(path: Path, expected_sha256: str):
    resolved = path.resolve()
    allowed_roots = [(_MODELS_DIR / "candidates").resolve(), _MODELS_DIR.resolve()]
    if not any(resolved == root or root in resolved.parents for root in allowed_roots):
        raise ValueError("Model artifact path is outside the models directory")
    if not resolved.is_file() or _file_sha256(resolved) != expected_sha256:
        raise ValueError("Model artifact is missing or its checksum does not match")
    model = joblib.load(resolved)
    if not callable(getattr(model, "predict_proba", None)):
        raise ValueError("Model does not support probability inference")
    schema = list(getattr(model, "feature_names_in_", []))
    if schema != FEATURE_NAMES:
        raise ValueError("Model feature schema is incompatible with transaction inference")
    probe = pd.DataFrame([{name: 0 for name in FEATURE_NAMES}], columns=FEATURE_NAMES)
    scores = model.predict_proba(probe)
    if scores.shape != (1, 2):
        raise ValueError("Model prediction output is incompatible")
    return model, resolved


def get_active_model_state() -> dict:
    path = _ACTIVE_MODEL_PATH
    if _POINTER_PATH.is_file():
        state = json.loads(_POINTER_PATH.read_text(encoding="utf-8"))
        path = Path(state["artifact"]).resolve()
        expected = state["sha256"]
    else:
        expected = _file_sha256(path)
    _validate_model(path, expected)
    return {"artifact": str(path), "sha256": expected}


def activate_runtime_model(path: Path, expected_sha256: str) -> bool:
    global _txn_model, _ACTIVE_MODEL_PATH
    try:
        model, resolved = _validate_model(path, expected_sha256)
        state = {"artifact": str(resolved), "sha256": expected_sha256}
        temp_path = _POINTER_PATH.with_suffix(".tmp")
        temp_path.write_text(json.dumps(state), encoding="utf-8")
        temp_path.replace(_POINTER_PATH)
        _txn_model = model
        _ACTIVE_MODEL_PATH = resolved
        return True
    except Exception as err:
        _LOGGER.error("Model activation rejected: %s", err)
        return False


try:
    if _POINTER_PATH.is_file():
        _txn_model = _validate_model(Path(json.loads(_POINTER_PATH.read_text(encoding="utf-8"))["artifact"]),
                                    json.loads(_POINTER_PATH.read_text(encoding="utf-8"))["sha256"])[0]
        _ACTIVE_MODEL_PATH = Path(json.loads(_POINTER_PATH.read_text(encoding="utf-8"))["artifact"]).resolve()
    else:
        _txn_model = joblib.load(_MODELS_DIR / "transaction_model.joblib")
except FileNotFoundError:
    _txn_model = None


def analyse_transaction(amount: float | None, recipient: str | None, payments_last_hour: int | None, is_new_recipient: bool | None) -> dict:
    has_behavioral_context = payments_last_hour is not None or is_new_recipient is not None
    cti_vpa_match = cti_matcher.match_vpa(recipient or "")

    if not has_behavioral_context and not cti_vpa_match:
        if amount is None and not recipient:
            return {"score": None, "reasons": [], "shap_explanation": []}
        reasons = [
            "An amount or recipient ID alone does not establish fraud; confirm the payee name in your UPI app before approving."
        ]
        if amount is not None and amount >= 10000:
            reasons.append("Confirm the entered amount carefully before authorizing the payment")
        return {"score": 0.0, "reasons": reasons, "shap_explanation": []}

    amount = amount or 0
    hour_of_day = datetime.now().hour
    reasons: list[str] = []

    if cti_vpa_match:
        reasons.append(f"CRITICAL: Recipient VPA '{recipient}' matches verified threat indicator in {cti_vpa_match['source_name']}")

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

    if _txn_model is not None and has_behavioral_context:
        row = pd.DataFrame([extract_features(amount, is_new_recipient, payments_last_hour, hour_of_day)])[FEATURE_NAMES]
        score = float(_txn_model.predict_proba(row)[0][1])
        shap_explanation = explain_prediction("transaction_model.joblib", row, FEATURE_LABELS)
    else:
        score = min(0.98, 0.03 + 0.15 * len(reasons))
        shap_explanation = []

    if cti_vpa_match:
        score = max(score, 0.90)

    if not reasons:
        reasons.append("No unusual transaction pattern was selected")

    out_res = {"score": round(min(score, 0.98), 3), "reasons": reasons, "shap_explanation": shap_explanation}
    if cti_vpa_match:
        out_res["cti_match"] = cti_vpa_match
    return out_res
