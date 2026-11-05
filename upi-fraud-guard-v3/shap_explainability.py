"""
Real, per-prediction explainability using SHAP (SHapley Additive
exPlanations) -- this replaces the "planned for a later phase" note in
earlier versions of the README with an actual implementation.

WHAT THIS FILE DOES (in plain terms):
The rule-based "reasons" text in each analyzer.py is readable, but it's
NOT a real explanation of the model -- it's a separate set of if-else
checks that happen to usually agree with the model. SHAP is different:
it mathematically decomposes ONE specific prediction into exactly how
much each individual feature pushed the score up or down, for THAT
input. This is genuine model attribution, not a proxy.

TreeExplainer works directly and exactly on Random Forest models (both
the URL model and the transaction model are Random Forests), with no
approximation needed and no separate background dataset required --
that's why both use the same tiny wrapper below.

Explainers are built ONCE per model (at import time) and reused, since
constructing a TreeExplainer takes a moment but running it per-prediction
is fast.
"""

import joblib
import shap
from pathlib import Path

_MODELS_DIR = Path(__file__).resolve().parent / "models"
_explainers: dict[str, shap.TreeExplainer] = {}


def _get_explainer(model_filename: str):
    if model_filename not in _explainers:
        model = joblib.load(_MODELS_DIR / model_filename)
        _explainers[model_filename] = shap.TreeExplainer(model)
    return _explainers[model_filename]


def explain_prediction(model_filename: str, feature_row, feature_labels: dict, top_n: int = 4) -> list[dict]:
    """
    Returns the top_n features that most pushed THIS prediction toward
    "risky", as a list of {feature, label, contribution, direction}.

    feature_row: a single-row pandas DataFrame with the exact feature
                 columns the model was trained on (order matters).
    feature_labels: maps raw feature names (e.g. "has_ip_address") to a
                     human-readable phrase (e.g. "Uses a raw IP address").
    """
    try:
        explainer = _get_explainer(model_filename)
        shap_values = explainer.shap_values(feature_row)
        # shape is (1, n_features, 2) for binary classifiers -- take the
        # "positive/risky" class (index 1) contributions for our one row.
        contributions = shap_values[0, :, 1]
    except Exception:
        return []  # if the model file is missing or SHAP fails for any reason, degrade gracefully

    pairs = list(zip(feature_row.columns, contributions))
    pairs.sort(key=lambda p: abs(p[1]), reverse=True)

    results = []
    for feature_name, contribution in pairs[:top_n]:
        if abs(contribution) < 1e-4:
            continue  # negligible effect on this specific prediction, not worth showing
        results.append({
            "feature": feature_name,
            "label": feature_labels.get(feature_name, feature_name),
            "contribution": round(float(contribution), 4),
            "direction": "increased_risk" if contribution > 0 else "decreased_risk",
        })
    return results
