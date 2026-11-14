"""
Risk Fusion Engine and Advisory Action Decision Engine for UPI Fraud Guard.

Combines signals from Message Classifier, Lexical URL/QR Parser, Transaction Velocity,
Dual-Feed Threat Intelligence, and CTI Indicators into a unified 0-100 risk score and 4-tier risk classification.
"""
from __future__ import annotations

LOW_THRESHOLD = 0.30
HIGH_THRESHOLD = 0.65
CRITICAL_THRESHOLD = 0.85


def fuse(message: dict, url: dict, transaction: dict) -> dict:
    signals = [
        ("Message", message.get("score")),
        (url.get("kind") or "Link / QR", url.get("score")),
        ("Transaction", transaction.get("score")),
    ]
    available = [(name, score) for name, score in signals if score is not None]

    # Collect CTI evidence from modules
    cti_evidence = []
    for mod in (message, url, transaction):
        if mod.get("cti_match"):
            cti_evidence.append(mod["cti_match"])

    if not available:
        return {
            "risk_score": 0.0,
            "risk_score_100": 0,
            "verdict": "Safe",
            "risk_tier": "Low",
            "recommended_action": "Proceed with normal payment precautions.",
            "reasons": ["Add at least one input to run a check."],
            "modules_used": [],
            "cti_evidence": cti_evidence,
        }

    weights = {
        "Message": 0.40,
        "URL": 0.35,
        "UPI QR payload": 0.35,
        "Link / QR": 0.35,
        "Transaction": 0.25,
    }

    denominator = sum(weights.get(name, 0.30) for name, _ in available)
    score = sum(weights.get(name, 0.30) * value for name, value in available) / denominator

    high_signals = sum(value >= HIGH_THRESHOLD for _, value in available)
    if high_signals >= 2:
        score = max(score, 0.72)

    # Boost score if CTI indicator match exists
    if cti_evidence:
        top_conf = max(item.get("confidence_score", 50) for item in cti_evidence)
        if top_conf >= 85:
            score = max(score, 0.88)
        else:
            score = max(score, 0.68)

    score = round(min(score, 0.99), 3)
    risk_score_100 = int(round(score * 100))

    if score >= CRITICAL_THRESHOLD:
        verdict = "High Risk"
        risk_tier = "Critical"
        recommended_action = "CRITICAL ALERT: Recommend stopping the transaction until independently verified."
    elif score >= HIGH_THRESHOLD:
        verdict = "High Risk"
        risk_tier = "High"
        recommended_action = "HIGH RISK: Warn user and recommend verifying payee identity directly before approving payment."
    elif score >= LOW_THRESHOLD:
        verdict = "Suspicious"
        risk_tier = "Medium"
        recommended_action = "MEDIUM RISK: Request additional payee verification before confirming payment."
    else:
        verdict = "Safe"
        risk_tier = "Low"
        recommended_action = "LOW RISK: Proceed with normal payment precautions."

    reason_sets = [message.get("reasons", []), url.get("reasons", []), transaction.get("reasons", [])]
    reasons = [reason for group in reason_sets for reason in group if not reason.startswith("No ")][:5]
    if not reasons:
        reasons = ["No strong fraud indicators were found in the supplied inputs"]

    return {
        "risk_score": score,
        "risk_score_100": risk_score_100,
        "verdict": verdict,
        "risk_tier": risk_tier,
        "recommended_action": recommended_action,
        "reasons": reasons,
        "modules_used": [name for name, _ in available],
        "cti_evidence": cti_evidence,
    }
