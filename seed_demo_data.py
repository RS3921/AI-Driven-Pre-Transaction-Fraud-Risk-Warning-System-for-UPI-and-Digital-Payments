"""Seeds the local audit log with realistic historical checks so the
Overview/Analytics charts show a real multi-day trend (like the
ShadowTrace reference) instead of a single flat point.

This is purely a DEMO/PRESENTATION convenience -- it does not touch
your models or API logic. Safe to run any time; by default it ADDS to
whatever's already in risk_checks.db. Use --reset to wipe the table
first for a clean-looking demo run.

Usage:
    python seed_demo_data.py            # add ~35 days of synthetic history
    python seed_demo_data.py --reset    # wipe existing checks first
    python seed_demo_data.py --days 60  # seed a longer window
"""
from __future__ import annotations
import argparse, json, math, random, sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "data" / "risk_checks.db"

SAFE_MESSAGES = [
    "Hi, sending your share for dinner last night, thanks!",
    "Paid the electricity bill, receipt attached.",
    "Rent for this month transferred, let me know once received.",
    "Thanks for the book, here's the amount we agreed on.",
]
FLAGGED_MESSAGES = [
    "URGENT! Your account will be blocked. Verify your UPI PIN now.",
    "Your KYC has expired, verify immediately to avoid suspension.",
    "Congratulations! You've won a cashback reward, claim it now.",
    "Refund pending -- confirm your bank details to receive it today.",
]
SAFE_URLS = ["", "upi://pay?pa=riya@upi&am=500", "upi://pay?pa=friend@okhdfc&am=250"]
FLAGGED_URLS = ["http://bit.ly/upi-verify-now", "http://upi-kyc-update.tk/verify", "http://secure-upi-refund.xyz"]

def shape(i: int, days: int) -> float:
    """Rise-then-fall curve with a small secondary bump, mirroring the
    reference chart's overall silhouette (a peak, a decline, a minor
    late bump, then a tail-off)."""
    peak1 = 18 * math.exp(-((i - days * 0.28) ** 2) / (days * 0.9))
    peak2 = 4 * math.exp(-((i - days * 0.78) ** 2) / (days * 0.6))
    return 2 + peak1 + peak2

def seed(days: int, reset: bool):
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS risk_checks (id INTEGER PRIMARY KEY, created_at TEXT, verdict TEXT, risk_score REAL, modules_used TEXT, reasons TEXT, message TEXT, url_or_qr TEXT, amount REAL, recipient TEXT)")
        if reset:
            conn.execute("DELETE FROM risk_checks")
        now = datetime.now(timezone.utc)
        today_midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
        inserted = 0
        for i in range(days):
            day = today_midnight - timedelta(days=(days - 1 - i))
            total = max(1, round(shape(i, days) + random.uniform(-1, 1)))
            for _ in range(total):
                flagged = random.random() < 0.55  # red line slightly above green, like the reference
                verdict = random.choice(["Suspicious", "High Risk"]) if flagged else "Safe"
                score = round(random.uniform(0.35, 0.95), 3) if flagged else round(random.uniform(0.02, 0.25), 3)
                message = random.choice(FLAGGED_MESSAGES if flagged else SAFE_MESSAGES)
                url = random.choice(FLAGGED_URLS if flagged else SAFE_URLS)
                # keep every timestamp within its own calendar day (and never past "now")
                max_seconds = 86399 if day < today_midnight else max(60, int((now - day).total_seconds()) - 1)
                created_at = (day + timedelta(seconds=random.randint(0, max_seconds))).isoformat()
                reasons = ["Message matches patterns seen in scam/spam training examples"] if flagged else ["Message does not resemble known scam patterns"]
                conn.execute(
                    "INSERT INTO risk_checks (created_at, verdict, risk_score, modules_used, reasons, message, url_or_qr, amount, recipient) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (created_at, verdict, score, json.dumps(["message", "url_qr"]), json.dumps(reasons), message, url, round(random.uniform(200, 50000), 2), "demo@upi"),
                )
                inserted += 1
        conn.commit()
    print(f"Seeded {inserted} demo checks across the last {days} days into {DB_PATH}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--days", type=int, default=35)
    parser.add_argument("--reset", action="store_true")
    args = parser.parse_args()
    seed(args.days, args.reset)
