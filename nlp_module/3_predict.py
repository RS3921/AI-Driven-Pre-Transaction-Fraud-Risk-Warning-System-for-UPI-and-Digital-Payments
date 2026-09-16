"""
Step 3: Use the trained model to score new, unseen messages.

This is the piece that will eventually plug into the API (and, further
down the line, into the risk-fusion layer alongside the URL/QR and
transaction modules).

Run it with:  python 3_predict.py
"""

import joblib
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent  # the upi-fraud-system folder
MODELS_DIR = BASE_DIR / "models"

model = joblib.load(MODELS_DIR / "nlp_model.joblib")
vectorizer = joblib.load(MODELS_DIR / "nlp_vectorizer.joblib")


def score_message(text: str) -> dict:
    """Takes a message and returns a risk score + verdict."""
    vec = vectorizer.transform([text])
    probability_spam = model.predict_proba(vec)[0][1]  # 0.0 to 1.0

    if probability_spam < 0.3:
        verdict = "Safe"
    elif probability_spam < 0.7:
        verdict = "Suspicious"
    else:
        verdict = "High Risk"

    return {
        "message": text,
        "risk_score": round(float(probability_spam), 3),
        "verdict": verdict,
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
