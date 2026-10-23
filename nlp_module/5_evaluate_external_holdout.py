"""Evaluate the message model on the sanitized, separate ScamShield test split.

This file is evaluation-only and is never loaded by the training script.
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

import joblib
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
from multilingual_message_rules import analyse_multilingual_message, is_explicitly_safe_context

DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
rows = pd.read_csv(DATA_DIR / "multilingual_external_holdout.csv").dropna(subset=["message", "target", "language"])
texts = rows["message"].astype(str).tolist()
vectorizer = joblib.load(MODELS_DIR / "nlp_vectorizer.joblib")
model = joblib.load(MODELS_DIR / "nlp_model.joblib")
model_scores = model.predict_proba(vectorizer.transform(texts))[:, 1]

by_language = defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0, "tn": 0})
for (_, row), raw_score in zip(rows.iterrows(), model_scores):
    message = str(row["message"])
    if is_explicitly_safe_context(message):
        raw_score = min(float(raw_score), 0.22)
    rule_score, _ = analyse_multilingual_message(message)
    predicted = int(max(float(raw_score), rule_score or 0.0) >= 0.30)
    actual = int(row["target"])
    key = "tp" if actual and predicted else "fn" if actual else "fp" if predicted else "tn"
    by_language[str(row["language"])][key] += 1

report = {}
for language, counts in by_language.items():
    tp, fn, fp, tn = (counts[k] for k in ("tp", "fn", "fp", "tn"))
    positive_support = tp + fn
    negative_support = fp + tn
    recall = tp / positive_support if positive_support else None
    specificity = tn / negative_support if negative_support else None
    precision = tp / (tp + fp) if tp + fp else None
    report[language] = {
        **counts,
        "samples": tp + fn + fp + tn,
        "risky_recall": round(recall, 4) if recall is not None else None,
        "safe_false_positive_rate": round(fp / negative_support, 4) if negative_support else None,
        "safe_specificity": round(specificity, 4) if specificity is not None else None,
        "precision": round(precision, 4) if precision is not None else None,
        "f1": round(2 * precision * recall / (precision + recall), 4)
        if precision is not None and recall is not None and precision + recall else None,
        "balanced_accuracy": round((recall + specificity) / 2, 4)
        if recall is not None and specificity is not None else None,
        "risky_support": positive_support,
        "safe_support": negative_support,
        "support_warning": "Small class support; interpret rates as unstable." if min(positive_support, negative_support) < 100 else None,
    }

metrics = {
    "dataset": "ScamShield Multilingual Smishing & Social Engineering Corpus",
    "dataset_split": "test (never used for training)",
    "notification_threshold": 0.30,
    "note": "External benchmark; source mix and class balance vary by language. Rates are reported with class supports. Hindi risky support and Hinglish safe support are small; these are not field-performance guarantees.",
    "marathi_coverage": "No independent Marathi examples are present in this external test split. Use the balanced Marathi smoke bucket only as a regression check, not as a performance estimate.",
    "total_samples": int(sum(v["samples"] for v in report.values())),
    "by_language": report,
}
out = MODELS_DIR / "multilingual_external_metrics.json"
out.write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"External multilingual holdout: {metrics['total_samples']} examples; saved {out}")
for language, values in report.items():
    fpr = values["safe_false_positive_rate"]
    print(
        f"{language}: risky recall={values['risky_recall']} "
        f"({values['tp']}/{values['risky_support']}), safe alert rate={fpr} "
        f"({values['fp']}/{values['safe_support']}); n={values['samples']}"
    )
