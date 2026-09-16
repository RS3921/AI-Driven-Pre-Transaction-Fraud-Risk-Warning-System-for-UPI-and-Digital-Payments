"""
Shared feature extraction for the transaction ML model.

Mirrors url_qr_module/url_features.py's role: one place where features
are computed, imported by both train_model.py and analyzer.py so
training and live scoring never drift apart.
"""


def extract_features(amount: float, is_new_recipient: bool, payments_last_hour: int, hour_of_day: int) -> dict:
    amount = amount or 0
    is_night = int(hour_of_day is not None and (hour_of_day >= 23 or hour_of_day <= 5))
    return {
        "amount": float(amount),
        "is_new_recipient": int(bool(is_new_recipient)),
        "payments_last_hour": int(payments_last_hour or 0),
        "is_night": is_night,
    }


FEATURE_NAMES = ["amount", "is_new_recipient", "payments_last_hour", "is_night"]
