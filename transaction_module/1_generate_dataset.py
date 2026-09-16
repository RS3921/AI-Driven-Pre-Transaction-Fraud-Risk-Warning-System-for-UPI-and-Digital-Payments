"""
Step 1: build a labeled transaction dataset -- "Transaction fraud
detection" was previously rule-based only ("not ML-trained yet").

WHAT THIS SCRIPT DOES (in plain terms):
Real transaction-fraud datasets (PaySim, IEEE-CIS) live on Kaggle and
require a manual login + download (PaySim alone is ~470MB / 6.3M rows)
that isn't reachable from this environment. So this generates a
synthetic but behaviourally realistic dataset instead, matching the
four signals this system actually collects from the user (amount,
new-recipient flag, recent payment frequency, time of day):

  - "normal": amount within a typical range, familiar recipients,
    normal frequency, daytime hours.
  - "anomalous": one or more of -- unusually large amount, a brand-new
    recipient, a burst of recent payments, or an odd-hour payment --
    the same behavioural red flags the existing rule-based checks in
    analyzer.py already look for (kept for the "reasons" text).

The dataset uses a REALISTIC class imbalance (~5% anomalous), not an
artificial 50/50 split, and 2_train_model.py explicitly compares
imbalance-handling strategies on it (baseline vs class_weight vs SMOTE).

NOTE FOR THE TEAM: this script now automatically uses REAL data if
data/paysim.csv is present (see load_real_paysim_data() below) --
otherwise it falls back to the synthetic generator so the pipeline
never breaks.

Run it with:  python 1_generate_dataset.py
"""

import random
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


df = load_real_paysim_data()
if df is None:
    existing_path = DATA_DIR / "transactions_dataset.csv"
    if existing_path.exists():
        # SAFETY GUARD: without this check, re-running this script (e.g.
        # if `python setup.py` is ever run again for an unrelated reason)
        # on a machine that doesn't have the large raw paysim.csv file
        # would silently OVERWRITE the already-good, real-data-trained
        # dataset with a much weaker synthetic one -- exactly the mistake
        # this note exists to prevent. If a real dataset is already here
        # (heuristically: more than 50,000 rows means it's almost
        # certainly the real PaySim-derived one, not the ~6,000-row
        # synthetic version), leave it alone and stop here.
        existing_row_count = sum(1 for _ in open(existing_path)) - 1
        if existing_row_count > 50_000:
            print(f"data/paysim.csv not found, but data/transactions_dataset.csv already "
                  f"contains {existing_row_count:,} rows (almost certainly the real PaySim-derived "
                  f"dataset from before). NOT overwriting it with synthetic data.")
            print("If you genuinely want to regenerate from scratch, either delete "
                  "data/transactions_dataset.csv first, or place a real data/paysim.csv here.")
            import sys
            sys.exit(0)
    print("data/paysim.csv not found -- using synthetic data with a realistic ~5% anomaly rate.")
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
