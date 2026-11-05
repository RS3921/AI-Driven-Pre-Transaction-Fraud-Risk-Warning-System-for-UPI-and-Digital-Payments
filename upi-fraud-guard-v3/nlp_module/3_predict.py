"""
Step 3: Use the trained model to score new, unseen messages.

This is the piece that will eventually plug into the API (and, further
down the line, into the risk-fusion layer alongside the URL/QR and
transaction modules).

Run it with:  python 3_predict.py
"""

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent  # the upi-fraud-system folder
sys.path.insert(0, str(BASE_DIR))
from api.main import score_message as score_api_message


def score_message(text: str) -> dict:
    """Use the same model, language rules and safe-context handling as the API."""
    result = score_api_message(text)
    score = float(result["score"])
    verdict = "High Risk" if score >= 0.65 else "Suspicious" if score >= 0.3 else "Safe"

    return {
        "message": text,
        "risk_score": round(score, 3),
        "verdict": verdict,
        "reasons": result["reasons"],
    }


if __name__ == "__main__":
    test_messages = [
        "Hey, are we still on for dinner tonight?",
        "URGENT! Your account will be BLOCKED. Click here to verify your UPI PIN immediately: bit.ly/xyz123",
        "Congratulations! You have WON a lottery of Rs 5,00,000. Send your bank details to claim now.",
        "Mom, I'll be home by 8, don't wait for dinner",
        "Dear customer your KYC has expired. Update immediately or your account will be suspended within 24 hours.",
    ]

    for msg in test_messages:
        result = score_message(msg)
        print(f"[{result['verdict']:<10}] (score={result['risk_score']})  {result['message'][:70]}")
