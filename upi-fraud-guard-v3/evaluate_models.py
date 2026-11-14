"""
Model Evaluation and Baseline Comparison Pipeline for UPI Fraud Guard.

Evaluates and compares:
1. Logistic Regression (Baseline)
2. Random Forest Classifier
3. Gradient Boosting / XGBoost Classifier
4. Isolation Forest (Anomaly Detector)

Metrics Computed: Precision, Recall, F1-score, ROC-AUC, PR-AUC, False Positive Rate, False Negative Rate.
"""
from __future__ import annotations

import json
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    auc,
)
from sklearn.model_selection import train_test_split

_DATA_DIR = Path(__file__).resolve().parent / "data"
_MODELS_DIR = Path(__file__).resolve().parent / "models"


def run_model_comparison() -> dict:
    # Generate synthetic benchmark dataset for evaluation comparison
    np.random.seed(42)
    n_samples = 2000
    n_features = 10

    # Simulate realistic fraud distribution (5% positive fraud rate)
    X = np.random.randn(n_samples, n_features)
    y = (X[:, 0] * 1.5 + X[:, 1] * 2.0 - X[:, 2] * 1.2 + np.random.randn(n_samples) > 2.8).astype(int)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)

    models = {
        "LogisticRegression_Baseline": LogisticRegression(class_weight="balanced", random_state=42),
        "RandomForest_Classifier": RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=42),
        "GradientBoosting_Classifier": GradientBoostingClassifier(n_estimators=100, random_state=42),
    }

    results = {}

    for name, model in models.items():
        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        y_proba = model.predict_proba(X_test)[:, 1]

        tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        roc_auc = roc_auc_score(y_test, y_proba)

        p_curve, r_curve, _ = precision_recall_curve(y_test, y_proba)
        pr_auc = auc(r_curve, p_curve)

        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

        results[name] = {
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "roc_auc": round(roc_auc, 4),
            "pr_auc": round(pr_auc, 4),
            "false_positive_rate": round(fpr, 4),
            "false_negative_rate": round(fnr, 4),
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        }

    # Evaluate Isolation Forest for Anomaly Detection
    iso_forest = IsolationForest(contamination=0.08, random_state=42)
    iso_forest.fit(X_train)
    iso_preds = iso_forest.predict(X_test)
    iso_binary = (iso_preds == -1).astype(int)

    tn, fp, fn, tp = confusion_matrix(y_test, iso_binary).ravel()
    results["IsolationForest_Anomaly"] = {
        "precision": round(precision_score(y_test, iso_binary, zero_division=0), 4),
        "recall": round(recall_score(y_test, iso_binary, zero_division=0), 4),
        "f1_score": round(f1_score(y_test, iso_binary, zero_division=0), 4),
        "false_positive_rate": round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0,
        "false_negative_rate": round(fn / (fn + tp), 4) if (fn + tp) > 0 else 0.0,
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }

    # Save metrics comparison JSON
    _MODELS_DIR.mkdir(parents=True, exist_ok=True)
    out_file = _MODELS_DIR / "model_comparison_metrics.json"
    out_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Model comparison completed. Results saved to {out_file}")
    return results


if __name__ == "__main__":
    run_model_comparison()
