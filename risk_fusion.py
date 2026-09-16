"""Risk fusion and user-facing explanation logic."""
from __future__ import annotations


def fuse(message: dict, url: dict, transaction: dict) -> dict:
    signals = [("Message", message.get("score")), (url.get("kind") or "Link / QR", url.get("score")), ("Transaction", transaction.get("score"))]
    available = [(name, score) for name, score in signals if score is not None]
    if not available:
        return {"risk_score": 0.0, "verdict": "Safe", "reasons": ["Add at least one input to run a check."], "modules_used": []}
    weights = {"Message": 0.4, "URL": 0.35, "UPI QR payload": 0.35, "Link / QR": 0.35, "Transaction": 0.25}
    denominator = sum(weights.get(name, 0.3) for name, _ in available)
    score = sum(weights.get(name, 0.3) * value for name, value in available) / denominator
    high_signals = sum(value >= 0.65 for _, value in available)
    if high_signals >= 2:
        score = max(score, 0.72)
    score = round(min(score, 0.99), 3)
    verdict = "High Risk" if score >= 0.65 else "Suspicious" if score >= 0.3 else "Safe"
    reason_sets = [message.get("reasons", []), url.get("reasons", []), transaction.get("reasons", [])]
    reasons = [reason for group in reason_sets for reason in group if not reason.startswith("No ")][:4]
    if not reasons:
        reasons = ["No strong fraud indicators were found in the supplied inputs"]
    return {"risk_score": score, "verdict": verdict, "reasons": reasons, "modules_used": [name for name, _ in available]}
