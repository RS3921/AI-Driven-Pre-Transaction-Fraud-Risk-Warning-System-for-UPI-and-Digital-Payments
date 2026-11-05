"""
Step 1: Load and clean the SMS dataset.

WHAT THIS SCRIPT DOES (in plain terms):
- Reads the raw CSV file
- Keeps only the two columns we care about: the label (spam/ham) and the message text
- Cleans up messy characters
- Saves a clean version we'll use for training

Run it with:  python 1_prepare_data.py
"""

import pandas as pd
from pathlib import Path

# This makes the script work no matter which folder you run it from.
BASE_DIR = Path(__file__).resolve().parent.parent  # the upi-fraud-system folder
DATA_DIR = BASE_DIR / "data"

# The raw file has extra empty columns and uses latin-1 encoding (not utf-8),
# which is common for older datasets scraped from the web.
df = pd.read_csv(DATA_DIR / "spam_raw.csv", encoding="latin-1")

# Keep only the first two columns and rename them to something readable
df = df.iloc[:, :2]
df.columns = ["label", "message"]

# Drop any rows that are missing a label or message
df = df.dropna(subset=["label", "message"])

# "ham" = legitimate message, "spam" = unwanted/scam message
# We convert this to numbers because ML models work with numbers, not words:
#   0 = ham (safe)
#   1 = spam (suspicious)
df["target"] = df["label"].map({"ham": 0, "spam": 1})

# Sanity check: make sure the mapping worked and nothing is missing
df = df.dropna(subset=["target"])
df["target"] = df["target"].astype(int)

print("Total messages:", len(df))
print(df["label"].value_counts())
print()
print("Sample rows:")
print(df[["label", "message"]].head(5).to_string(index=False))

# Save the cleaned version so later scripts don't need to redo this step
df[["message", "target"]].to_csv(DATA_DIR / "messages_clean.csv", index=False)
print("\nSaved cleaned data to data/messages_clean.csv")
