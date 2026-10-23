"""Evaluate explicitly consented, native-speaker-reviewed language examples.

This reports missed risky examples and false alerts by language. It does not
train or alter the model. Raw messages and reviewer/source IDs never go into
the metrics output. See data/NATIVE_LANGUAGE_DATA_COLLECTION.md first.
"""
from __future__ import annotations

import csv
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
sys.path.insert(0, str(BASE_DIR))
from api.main import score_message

INPUT = DATA_DIR / "native_language_reviewed.csv"
OUTPUT = BASE_DIR / "models" / "native_language_reviewed_metrics.json"
THRESHOLD = 0.30
REQUIRED = {
    "record_id", "language", "message", "target", "consent_for_evaluation",
    "review_status", "native_speaker_reviewed", "source_group",
}


def normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().casefold()


def ratio(n: int, d: int) -> float | None:
    return round(n / d, 4) if d else None


def training_texts() -> set[str]:
    base = pd.read_csv(DATA_DIR / "messages_clean.csv").dropna(subset=["message", "target"])
    train, _, _, _ = train_test_split(
        base["message"].astype(str), base["target"].astype(int),
        test_size=0.2, random_state=42, stratify=base["target"].astype(int),
    )
    known = set(train.map(normalize))
    for filename in (
        "message_training_additions.csv", "multilingual_training_subset.csv",
        "marathi_synthetic_supplement.csv", "marathi_translated_training.csv",
    ):
        path = DATA_DIR / filename
        if path.exists():
            with path.open(encoding="utf-8-sig", newline="") as handle:
                for row in csv.DictReader(handle):
                    if row.get("message"):
                        known.add(normalize(row["message"]))
    return known


if not INPUT.is_file():
    raise SystemExit(
        f"No reviewed evaluation file found at {INPUT}. Copy the template to "
        "data/native_language_reviewed.csv and add only consented, approved, "
        "native-speaker-reviewed, redacted examples."
    )

with INPUT.open(encoding="utf-8-sig", newline="") as handle:
    reader = csv.DictReader(handle)
    missing = REQUIRED - set(reader.fieldnames or [])
    if missing:
        raise SystemExit(f"Missing CSV columns: {', '.join(sorted(missing))}")
    rows = list(reader)

trained = training_texts()
eligible: list[dict[str, str | int]] = []
exclusions = defaultdict(int)
seen_ids: set[str] = set()
seen_messages: set[tuple[str, str]] = set()
for row in rows:
    rid = row.get("record_id", "").strip()
    language = row.get("language", "").strip()
    message = row.get("message", "").strip()
    group = row.get("source_group", "").strip()
    if row.get("consent_for_evaluation", "").strip().lower() != "yes":
        exclusions["no_evaluation_consent"] += 1
        continue
    if row.get("review_status", "").strip().lower() != "approved" or row.get("native_speaker_reviewed", "").strip().lower() != "yes":
        exclusions["not_native_speaker_approved"] += 1
        continue
    if not rid or not language or not message or not group:
        exclusions["missing_required_value"] += 1
        continue
    if len(language) > 40 or not re.fullmatch(r"[A-Za-z][A-Za-z -]{0,39}", language):
        exclusions["invalid_language_name"] += 1
        continue
    if rid in seen_ids:
        exclusions["duplicate_record_id"] += 1
        continue
    try:
        target = int(row["target"])
    except (TypeError, ValueError):
        exclusions["invalid_label"] += 1
        continue
    if target not in (0, 1):
        exclusions["invalid_label"] += 1
        continue
    key = (language.casefold(), normalize(message))
    if key[1] in trained:
        exclusions["exact_training_duplicate"] += 1
        continue
    if key in seen_messages:
        exclusions["duplicate_evaluation_message"] += 1
        continue
    seen_ids.add(rid)
    seen_messages.add(key)
    eligible.append({"language": language, "message": message, "target": target, "source_group": group})

if not eligible:
    raise SystemExit("No eligible reviewed examples found; see data/NATIVE_LANGUAGE_DATA_COLLECTION.md.")

counts = defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0, "tn": 0})
independent_groups = defaultdict(lambda: {0: set(), 1: set()})
for row in eligible:
    expected = int(row["target"])
    result = score_message(str(row["message"]))
    predicted = int(float(result["score"] or 0.0) >= THRESHOLD)
    key = "tp" if expected and predicted else "fn" if expected else "fp" if predicted else "tn"
    counts[str(row["language"])][key] += 1
    independent_groups[str(row["language"])][expected].add(str(row["source_group"]))

by_language = {}
for language, c in sorted(counts.items()):
    risky = c["tp"] + c["fn"]
    safe = c["tn"] + c["fp"]
    precision = ratio(c["tp"], c["tp"] + c["fp"])
    recall = ratio(c["tp"], risky)
    specificity = ratio(c["tn"], safe)
    safe_groups = len(independent_groups[language][0])
    risky_groups = len(independent_groups[language][1])
    low_support = min(risky, safe) < 100 or min(risky_groups, safe_groups) < 20
    by_language[language] = {
        **c,
        "samples": risky + safe,
        "risky_support": risky,
        "safe_support": safe,
        "independent_safe_source_groups": safe_groups,
        "independent_risky_source_groups": risky_groups,
        "missed_risky_rate": ratio(c["fn"], risky),
        "risky_recall": recall,
        "safe_false_positive_rate": ratio(c["fp"], safe),
        "precision": precision,
        "f1": round(2 * precision * recall / (precision + recall), 4) if precision is not None and recall is not None and precision + recall else None,
        "balanced_accuracy": round((recall + specificity) / 2, 4) if recall is not None and specificity is not None else None,
        "support_warning": "Preliminary: aim for at least 100 examples and 20 independent source groups in both safe and risky classes." if low_support else None,
    }

report = {
    "evaluation_type": "consented, redacted, native-speaker-reviewed holdout; does not train the model",
    "threshold": THRESHOLD,
    "eligible_samples": len(eligible),
    "languages": by_language,
    "excluded_counts": dict(exclusions),
    "privacy": "Aggregate counts only; no message text, record IDs, or source-group values are written to this report.",
    "limitations": [
        "Results depend on the collection population and review quality; they do not prove performance on all users or future scams.",
        "Exact text overlap with known training examples is excluded; paraphrase or campaign leakage may still exist.",
        "Low safe or risky support makes the corresponding rate unstable.",
    ],
}
OUTPUT.parent.mkdir(parents=True, exist_ok=True)
OUTPUT.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
print(f"Reviewed evaluation rows: {len(eligible)} at risk threshold {THRESHOLD:.2f}")
for language, metric in by_language.items():
    print(
        f"{language}: missed risky={metric['fn']}/{metric['risky_support']} "
        f"({metric['missed_risky_rate']}), safe false alerts={metric['fp']}/{metric['safe_support']} "
        f"({metric['safe_false_positive_rate']}), precision={metric['precision']}, "
        f"support warning={metric['support_warning']}"
    )
print(f"Aggregate metrics saved to {OUTPUT}; messages and identifiers were not copied into the report.")
