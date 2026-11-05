"""Create a leakage-safe Marathi translation train/holdout split.

The source messages are machine-translated Marathi, not native-speaker-written
examples. Split by the original English message so the translated copy of an
English training/test example cannot cross the same boundary.
"""
from __future__ import annotations

from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
source_path = DATA_DIR / "marathi_sms_translated_source.csv"
base_path = DATA_DIR / "messages_clean.csv"

translated = pd.read_csv(source_path).dropna(subset=["message", "source_text", "target"])
translated["message"] = translated["message"].astype(str).str.strip()
translated["source_text"] = translated["source_text"].astype(str).str.strip()
translated["target"] = translated["target"].astype(int)
translated = translated[(translated.message != "") & (translated.source_text != "")]
translated = translated.drop_duplicates(subset=["source_text"], keep="first")

base = pd.read_csv(base_path).dropna(subset=["message", "target"])
X = base["message"].astype(str)
y = base["target"].astype(int)
X_train, X_test, _, _ = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
test_sources = set(X_test)
train_sources = set(X_train) - test_sources

train = translated[translated.source_text.isin(train_sources)].copy()
holdout = translated[translated.source_text.isin(test_sources)].copy()
if train.empty or holdout.empty:
    raise SystemExit("Could not make Marathi train/holdout groups from the original SMS split.")
if set(train.source_text) & set(holdout.source_text):
    raise SystemExit("Data leakage: a source SMS appears in both Marathi splits.")

train["language"] = "Marathi"
train["source_dataset"] = "SMS Spam Multilingual Collection Dataset; machine-translated Marathi"
holdout["language"] = "Marathi"
holdout["source_dataset"] = "SMS Spam Multilingual Collection Dataset; machine-translated Marathi"
train.to_csv(DATA_DIR / "marathi_translated_training.csv", index=False, encoding="utf-8")
holdout.to_csv(DATA_DIR / "marathi_translated_holdout.csv", index=False, encoding="utf-8")

print(f"Marathi machine-translated supplement: train={len(train)}, holdout={len(holdout)}")
print("Train labels:", train.target.value_counts().sort_index().to_dict())
print("Holdout labels:", holdout.target.value_counts().sort_index().to_dict())
print("Source messages are grouped across the split; they are not native-speaker-reviewed.")
