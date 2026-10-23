"""
Step 1: build a labeled transaction dataset -- "Transaction fraud
detection" was previously rule-based only ("not ML-trained yet").

WHAT THIS SCRIPT DOES (in plain terms):
The repository includes the processed PaySim-derived transaction table.
The raw PaySim CSV is optional and is not committed because it is about
494 MB. Normal setup reuses the processed table. If it is missing, this script imports data/paysim.csv and maps its
columns to the four features used by this project (amount,
new-recipient flag, recent payment frequency, time of day). Synthetic
data is only a fallback if neither dataset is available.

  - "normal": amount within a typical range, familiar recipients,
    normal frequency, daytime hours.
  - "anomalous": one or more of -- unusually large amount, a brand-new
    recipient, a burst of recent payments, or an odd-hour payment --
    the same behavioural red flags the existing rule-based checks in
    analyzer.py already look for (kept for the "reasons" text).

The dataset uses a REALISTIC class imbalance (~5% anomalous), not an
artificial 50/50 split, and 2_train_model.py explicitly compares
imbalance-handling strategies on it (baseline vs class_weight vs SMOTE).

To explicitly regenerate the processed table from raw data, set
UPI_FRAUD_GUARD_REBUILD_TRANSACTIONS=1 before running python setup.py.

Run it with:  python 1_generate_dataset.py
"""

import random
import os
import pandas as pd
from pathlib import Path

random.seed(42)

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

N_TOTAL = 6000
ANOMALY_RATE = 0.05

# How much of the real PaySim data to keep after feature engineering.
# PaySim has 6.36M rows and only ~8,200 fraud cases (~0.13%) -- keeping
# every non-fraud row would make training slow for little benefit, so
# every fraud row is kept, plus a random sample of non-fraud rows sized
# to land on a realistic-but-workable ~3% anomaly rate for training.
MAX_NON_FRAUD_SAMPLE = 260_000


def load_real_paysim_data() -> pd.DataFrame | None:
    """If data/paysim.csv exists (the real Kaggle PaySim dataset), load and reshape it
    onto this project's 4-feature schema: amount, is_new_recipient,
    payments_last_hour, hour_of_day."""
    paysim_path = DATA_DIR / "paysim.csv"
    if not paysim_path.exists():
        return None

    print("Found data/paysim.csv -- using REAL PaySim data instead of synthetic generation.")
    print("(This is a large file -- loading and feature-engineering may take a minute.)")
    raw = pd.read_csv(paysim_path)
    print(f"Loaded {len(raw):,} real transactions "
          f"({raw['isFraud'].sum():,} fraud, {raw['isFraud'].mean() * 100:.3f}% -- PaySim's real-world fraud rate)")

    # PaySim's "step" is an hour-index (1 step = 1 simulated hour) -- this
    # maps directly onto our hour_of_day feature.
    raw["hour_of_day"] = raw["step"] % 24

    # "is_new_recipient": has this nameOrig ever sent to this nameDest
    # before this row, anywhere earlier in the full transaction log?
    raw = raw.sort_values(["nameOrig", "step"]).reset_index(drop=True)
    pair_seen_count = raw.groupby(["nameOrig", "nameDest"]).cumcount()
    raw["is_new_recipient"] = (pair_seen_count == 0).astype(int)

    # "payments_last_hour": how many other transactions did this same
    # sender make within the same simulated hour (step)? PaySim doesn't
    # track true wall-clock bursts, so this is the closest real proxy
    # available in the dataset -- documented approximation, same spirit
    # as the rest of this project's honest-limitations notes.
    raw["payments_last_hour"] = raw.groupby(["nameOrig", "step"])["step"].transform("count") - 1

    df = raw.rename(columns={"isFraud": "target"})[
        ["amount", "is_new_recipient", "payments_last_hour", "hour_of_day", "target"]
    ]

    fraud_rows = df[df["target"] == 1]
    non_fraud_rows = df[df["target"] == 0]
    if len(non_fraud_rows) > MAX_NON_FRAUD_SAMPLE:
        non_fraud_rows = non_fraud_rows.sample(n=MAX_NON_FRAUD_SAMPLE, random_state=42)

    combined = pd.concat([fraud_rows, non_fraud_rows]).sample(frac=1, random_state=42).reset_index(drop=True)
    return combined



def make_normal():
    return {
        "amount": round(max(50, random.gauss(1800, 1200)), 2),
        "is_new_recipient": random.choices([0, 1], weights=[0.85, 0.15])[0],
        "payments_last_hour": random.choices([0, 1, 2], weights=[0.75, 0.18, 0.07])[0],
        "hour_of_day": random.choice(list(range(7, 23))),
        "target": 0,
    }


def make_anomalous():
    style = random.choice(["large_amount", "new_recipient_burst", "rapid_fire", "odd_hour"])
    if style == "large_amount":
        return {
            "amount": round(random.uniform(15000, 100000), 2),
            "is_new_recipient": random.choices([0, 1], weights=[0.4, 0.6])[0],
            "payments_last_hour": random.randint(0, 2),
            "hour_of_day": random.randint(0, 23),
            "target": 1,
        }
    if style == "new_recipient_burst":
        return {
            "amount": round(random.uniform(2000, 20000), 2),
            "is_new_recipient": 1,
            "payments_last_hour": random.randint(0, 1),
            "hour_of_day": random.randint(0, 23),
            "target": 1,
        }
    if style == "rapid_fire":
        return {
            "amount": round(random.uniform(500, 5000), 2),
            "is_new_recipient": random.choices([0, 1], weights=[0.5, 0.5])[0],
            "payments_last_hour": random.randint(5, 15),
            "hour_of_day": random.randint(0, 23),
            "target": 1,
        }
    return {  # odd_hour
        "amount": round(random.uniform(3000, 20000), 2),
        "is_new_recipient": random.choices([0, 1], weights=[0.5, 0.5])[0],
        "payments_last_hour": random.randint(0, 2),
        "hour_of_day": random.choice([0, 1, 2, 3, 4, 23]),
        "target": 1,
    }


existing_path = DATA_DIR / "transactions_dataset.csv"
force_rebuild = os.environ.get("UPI_FRAUD_GUARD_REBUILD_TRANSACTIONS", "").strip() == "1"

# The ZIP contains both the raw source and processed training table. Reuse
# the processed table during ordinary setup so users do not reread 493 MB on
# every run. The optional environment flag explicitly rebuilds it from raw.
if existing_path.exists() and not force_rebuild:
    df = pd.read_csv(existing_path)
    expected_columns = {"amount", "is_new_recipient", "payments_last_hour", "hour_of_day", "target"}
    if not expected_columns.issubset(df.columns):
        raise ValueError(f"{existing_path} is missing required columns: {sorted(expected_columns - set(df.columns))}")
    print(f"Using bundled processed data/transactions_dataset.csv ({len(df):,} rows).")
    if (DATA_DIR / "paysim.csv").exists():
        print("Raw PaySim data was found at data/paysim.csv; it is not re-imported during normal setup.")
    print("To intentionally rebuild the processed dataset from raw PaySim, set UPI_FRAUD_GUARD_REBUILD_TRANSACTIONS=1 before python setup.py.")
else:
    df = load_real_paysim_data()
    if df is None:
        print("No processed transaction table or data/paysim.csv found -- using synthetic demo data (~5% anomaly rate).")
        n_anomalous = int(N_TOTAL * ANOMALY_RATE)
        n_normal = N_TOTAL - n_anomalous
        rows = [make_normal() for _ in range(n_normal)] + [make_anomalous() for _ in range(n_anomalous)]
        df = pd.DataFrame(rows).sample(frac=1, random_state=42).reset_index(drop=True)

print("\nTotal transactions:", len(df))
counts = df["target"].value_counts().rename({0: "normal", 1: "anomalous"})
print(counts)
print(f"Anomaly rate: {counts.get('anomalous', 0) / len(df) * 100:.2f}%")
print("\nSample rows:")
print(df.head(6).to_string(index=False))

df.to_csv(DATA_DIR / "transactions_dataset.csv", index=False)
print("\nSaved dataset to data/transactions_dataset.csv")
