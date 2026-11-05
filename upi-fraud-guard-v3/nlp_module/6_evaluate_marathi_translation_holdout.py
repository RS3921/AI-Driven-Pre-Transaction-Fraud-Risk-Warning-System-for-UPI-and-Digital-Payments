"""Evaluate on source-group-held-out, machine-translated Marathi SMS.

This is a translation-transfer diagnostic, not a real-world Marathi accuracy
claim. The source English SMS and its Marathi translation are kept on the same
side of the original English train/test boundary.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import joblib
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
MODELS_DIR = BASE_DIR / "models"
THRESHOLD = 0.30

sys_path = str(BASE_DIR)
import sys
if sys_path not in sys.path:
    sys.path.insert(0, sys_path)
from multilingual_message_rules import analyse_multilingual_message, is_explicitly_safe_context

rows = pd.read_csv(DATA_DIR / "marathi_translated_holdout.csv").dropna(subset=["message", "target", "source_text"])
model = joblib.load(MODELS_DIR / "nlp_model.joblib")
vectorizer = joblib.load(MODELS_DIR / "nlp_vectorizer.joblib")
texts = rows["message"].astype(str).tolist()
raw_scores = model.predict_proba(vectorizer.transform(texts))[:, 1]
counts = Counter()

for message, actual_value, raw_score in zip(texts, rows["target"].astype(int), raw_scores):
    if is_explicitly_safe_context(message):
        raw_score = min(float(raw_score), 0.22)
    rule_score, _ = analyse_multilingual_message(message)
    predicted = int(max(float(raw_score), rule_score or 0.0) >= THRESHOLD)
    actual = int(actual_value)
    counts["tp" if actual and predicted else "fn" if actual else "fp" if predicted else "tn"] += 1

tp, fn, fp, tn = (counts[key] for key in ("tp", "fn", "fp", "tn"))
positive, negative = tp + fn, tn + fp
precision = tp / (tp + fp) if tp + fp else None
recall = tp / positive if positive else None
specificity = tn / negative if negative else None
metrics = {
    "dataset": "SMS Spam Multilingual Collection Dataset; Marathi column translated from UCI SMS Spam Collection using M2M100_418M",
    "evaluation_type": "source-message-grouped translation-transfer holdout; not natural Marathi field evaluation",
    "notification_threshold": THRESHOLD,
    "samples": int(len(rows)),
    "safe_support": negative,
    "risky_support": positive,
    "tp": tp,
    "fn": fn,
    "fp": fp,
    "tn": tn,
    "precision": round(precision, 4) if precision is not None else None,
    "risky_recall": round(recall, 4) if recall is not None else None,
    "safe_false_positive_rate": round(fp / negative, 4) if negative else None,
    "balanced_accuracy": round((recall + specificity) / 2, 4) if recall is not None and specificity is not None else None,
    "limitations": [
        "The Marathi texts were machine-translated from English and are not native-speaker-written or reviewed.",
        "The source corpus is general SMS ham/spam, not specifically UPI fraud.",
        "Use this only as a translation-transfer diagnostic; collect consented, native-speaker-reviewed Marathi messages before making real-world performance claims.",
    ],
}
out = MODELS_DIR / "marathi_translated_metrics.json"
out.write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"Marathi translated holdout: n={len(rows)}, risky caught={tp}/{positive}, safe alerts={fp}/{negative}")
print(f"Recall={metrics['risky_recall']}; safe false-alert rate={metrics['safe_false_positive_rate']}; balanced accuracy={metrics['balanced_accuracy']}")
print("This is a machine-translation diagnostic, not a field-accuracy claim.")
print(f"Metrics saved to {out}")
