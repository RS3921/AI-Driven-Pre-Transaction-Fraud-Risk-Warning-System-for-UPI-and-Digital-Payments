"""Parse UPI payment URIs and flag malformed or unusual request fields."""
from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation
from urllib.parse import parse_qsl, urlparse

_VPA = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}@[A-Za-z][A-Za-z0-9.-]{1,62}$")


def parse_upi_payment_uri(value: str) -> dict | None:
    """Return display-safe payment fields for a UPI `upi://pay` URI.

    A valid URI only means its fields can be parsed. It does not authenticate
    or establish trust in the payee.
    """
    value = (value or "").strip()
    parsed = urlparse(value)
    if parsed.scheme.lower() != "upi" or parsed.netloc.lower() != "pay" or parsed.path not in ("", "/"):
        return None

    raw = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=False)
    grouped: dict[str, list[str]] = {}
    for key, value in raw:
        grouped.setdefault(key.lower(), []).append(value.strip())
    params = {key: values[-1] for key, values in grouped.items() if values}
    vpa = params.get("pa", "")
    name = params.get("pn", "")
    raw_amount = params.get("am", "")
    raw_currency = params.get("cu", "")
    currency = raw_currency.upper() if raw_currency else "INR"
    flags: list[str] = []
    amount: str | None = None
    amount_value: Decimal | None = None

    duplicated = sorted(key for key, values in grouped.items() if len(values) > 1)
    if duplicated:
        flags.append(f"QR repeats payment fields ({', '.join(duplicated[:4])}); values may be ambiguous")

    if not vpa:
        flags.append("Required payee UPI ID (pa) is missing")
    elif not _VPA.fullmatch(vpa):
        flags.append("Payee UPI ID has an unusual format")
    # UPI clients do not all include a payee display name in static codes.
    # Its absence is informational, not evidence that a QR is fraudulent.
    if name and (len(name) > 100 or any(ord(char) < 32 for char in name)):
        flags.append("Display name is unusually long or contains control characters")

    if raw_amount:
        try:
            if len(raw_amount) > 15 or not re.fullmatch(r"\d+(?:\.\d{1,2})?", raw_amount):
                raise InvalidOperation
            amount_value = Decimal(raw_amount)
            if not amount_value.is_finite() or amount_value <= 0:
                raise InvalidOperation
            amount = format(amount_value, "f")
        except (InvalidOperation, ValueError):
            flags.append("Amount field is not a valid positive number")
            amount = raw_amount

    if raw_currency and not re.fullmatch(r"[A-Z]{3}", currency):
        flags.append("Currency code is malformed")
    elif raw_currency and currency != "INR":
        flags.append(f"Currency {currency} is unusual for an Indian UPI payment")
    # Some valid payment QRs omit currency. We show INR as an assumption in
    # the UI without raising the risk score just for that omission.

    if amount_value is not None and amount_value >= Decimal("10000"):
        flags.append("Requested amount is ₹10,000 or more; verify it carefully")

    return {
        "payee_vpa": vpa or None,
        "payee_name": name or None,
        "amount": amount,
        "currency": currency,
        "currency_assumed": not bool(raw_currency),
        "merchant_code": params.get("mc") or None,
        "transaction_note": params.get("tn") or None,
        "reference_id": params.get("tr") or params.get("tid") or None,
        "flags": flags,
        "well_formed": bool(vpa) and not any(
            marker in flag.lower()
            for flag in flags
            for marker in ("missing", "unusual format", "not a valid", "malformed", "ambiguous", "control characters")
        ),
    }
