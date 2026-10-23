"""Run the balanced, curated multilingual message regression smoke set.

This is a regression check, not an independent accuracy benchmark. It has a
small, equal number of safe and risky hand-authored examples per language.
Use 5_evaluate_external_holdout.py for the larger public English/Hindi test
set. There is no independent Marathi benchmark in the current project.
"""
from __future__ import annotations

import csv
import json
import sys
from collections import defaultdict
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
from api.main import score_message

THRESHOLD = 0.30
EXPECTED_LANGUAGES = {"English", "Hindi", "Marathi", "Hinglish", "Marathlish"}


def ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def evaluate(rows: list[dict[str, str]]) -> dict:
    counts = defaultdict(lambda: {"tp": 0, "fp": 0, "tn": 0, "fn": 0})
    for row in rows:
        expected = int(row["target"])
        result = score_message(row["message"])
        predicted = int(float(result["score"] or 0.0) >= THRESHOLD)
        key = "tp" if expected and predicted else "fn" if expected else "fp" if predicted else "tn"
        counts[row["language"]][key] += 1

    report = {}
    for language, c in sorted(counts.items()):
        positive = c["tp"] + c["fn"]
        negative = c["tn"] + c["fp"]
        total = positive + negative
        recall = ratio(c["tp"], positive)
        specificity = ratio(c["tn"], negative)
        report[language] = {
            **c,
            "samples": total,
            "safe_support": negative,
            "risky_support": positive,
            "precision": ratio(c["tp"], c["tp"] + c["fp"]),
            "risky_recall": recall,
            "safe_false_positive_rate": ratio(c["fp"], negative),
            "balanced_accuracy": round((recall + specificity) / 2, 4)
            if recall is not None and specificity is not None else None,
            "accuracy": ratio(c["tp"] + c["tn"], total),
        }
    return report


data_path = BASE_DIR / "data" / "multilingual_holdout_eval.csv"
with data_path.open(encoding="utf-8", newline="") as handle:
    samples = list(csv.DictReader(handle))

if not samples:
    raise SystemExit(f"No evaluation rows found in {data_path}")
observed = {row["language"] for row in samples}
if observed != EXPECTED_LANGUAGES:
    raise SystemExit(f"Expected language buckets {sorted(EXPECTED_LANGUAGES)}, got {sorted(observed)}")
for language in sorted(EXPECTED_LANGUAGES):
    subset = [row for row in samples if row["language"] == language]
    labels = [int(row["target"]) for row in subset]
    if len(subset) != 12 or labels.count(0) != 6 or labels.count(1) != 6:
        raise SystemExit(f"{language} must have exactly 12 examples: 6 safe and 6 risky")

metrics = {
    "evaluation_type": "balanced curated regression smoke test; not an independent benchmark",
    "description": "12 hand-authored examples per language bucket (6 safe, 6 risky); use external holdout results for broader evidence.",
    "notification_threshold": THRESHOLD,
    "total_samples": len(samples),
    "by_language": evaluate(samples),
    "limitations": [
        "Small hand-authored sets check known examples and regressions; they cannot estimate real-world accuracy.",
        "Marathi has no independent external test corpus in this project. Its 12-example bucket is only a smoke check.",
        "Hinglish and Marathlish are reported separately from native-script Hindi and Marathi.",
    ],
}
output_path = BASE_DIR / "models" / "multilingual_eval_metrics.json"
output_path.write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")

print(f"Balanced multilingual regression smoke set: {len(samples)} examples; threshold={THRESHOLD:.2f}")
for language, values in metrics["by_language"].items():
    print(
        f"{language}: risky caught={values['tp']}/{values['risky_support']}, "
        f"safe alerts={values['fp']}/{values['safe_support']}, "
        f"balanced accuracy={values['balanced_accuracy']}"
    )
print("Reminder: these small curated scores are smoke-test results, not accuracy claims.")
print(f"Detailed counts saved to {output_path}")
