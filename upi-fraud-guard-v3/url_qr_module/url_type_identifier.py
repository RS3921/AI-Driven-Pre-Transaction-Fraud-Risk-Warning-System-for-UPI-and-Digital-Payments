"""
URL Intent & Type Identification Layer for AUIE.

Classifies any input string or URL into structured classifications:
- UPI_PAYMENT_LINK
- PAYMENT_GATEWAY
- MERCHANT_WEBSITE
- SHORTENED_URL
- GENERAL_WEBSITE
- UNKNOWN_URL_TYPE
"""
from __future__ import annotations

import re
import urllib.parse
from typing import Any, Dict

KNOWN_PAYMENT_GATEWAYS = {
    "razorpay.com", "payu.in", "billdesk.com", "cashfree.com", "ccavenue.com",
    "paytm.com", "phonepe.com", "stripe.com", "paypal.com", "instamojo.com",
    "secure.payu.in", "checkout.razorpay.com", "api.razorpay.com", "juspay.in",
}

KNOWN_MERCHANTS = {
    "amazon.in", "amazon.com", "flipkart.com", "myntra.com", "meesho.com",
    "swiggy.com", "zomato.com", "nykaa.com", "ajio.com", "bigbasket.com",
    "blinkit.com", "zepto.com", "tata-cliq.com", "bookmyshow.com",
    "makemytrip.com", "yatra.com", "goibibo.com", "redbus.in", "uber.com", "olacabs.com",
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "goo.su", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorte.st", "rb.gy", "shorturl.at",
}


def classify_url_type(raw_url: str) -> Dict[str, Any]:
    """
    Classifies a raw URL or payment string into a structured URL type classification.
    Returns dictionary with url_type, category_description, and parsed metadata.
    """
    clean = (raw_url or "").strip()
    if not clean:
        return {
            "url_type": "UNKNOWN_URL_TYPE",
            "category": "Unknown / Empty Input",
            "is_payment_related": False,
            "domain": "",
            "path": "",
        }

    # 1. UPI Payment Link / QR URI
    if clean.lower().startswith("upi://") or "pa=" in clean.lower():
        return {
            "url_type": "UPI_PAYMENT_LINK",
            "category": "UPI Deep Link / Payment QR Payload",
            "is_payment_related": True,
            "domain": "upi.protocol",
            "path": clean,
        }

    # Normalize HTTP/HTTPS candidate
    candidate = clean if "://" in clean else f"https://{clean}"
    try:
        parsed = urllib.parse.urlparse(candidate)
        host = (parsed.hostname or "").lower().rstrip(".")
        if host.startswith("www."):
            host = host[4:]
        path = parsed.path or "/"
    except Exception:
        return {
            "url_type": "UNKNOWN_URL_TYPE",
            "category": "Malformed / Unparseable URL",
            "is_payment_related": False,
            "domain": "",
            "path": clean,
        }

    if not host:
        return {
            "url_type": "UNKNOWN_URL_TYPE",
            "category": "Missing Hostname",
            "is_payment_related": False,
            "domain": "",
            "path": clean,
        }

    # 2. URL Shortener
    if host in SHORTENER_DOMAINS:
        return {
            "url_type": "SHORTENED_URL",
            "category": "URL Shortener Service",
            "is_payment_related": False,
            "domain": host,
            "path": path,
        }

    # 3. Payment Gateway Checkout URL
    is_gateway = any(host == gw or host.endswith("." + gw) for gw in KNOWN_PAYMENT_GATEWAYS) or "checkout" in host or "pay" in host
    if is_gateway and any(term in f"{host}{path}".lower() for term in ["pay", "checkout", "gateway", "bill", "transaction", "invoice"]):
        return {
            "url_type": "PAYMENT_GATEWAY",
            "category": "Hosted Payment Gateway / Checkout Flow",
            "is_payment_related": True,
            "domain": host,
            "path": path,
        }

    # 4. Merchant Website
    is_merchant = any(host == m or host.endswith("." + m) for m in KNOWN_MERCHANTS)
    if is_merchant:
        return {
            "url_type": "MERCHANT_WEBSITE",
            "category": "E-Commerce / Merchant Portal",
            "is_payment_related": False,
            "domain": host,
            "path": path,
        }

    # 5. General Website
    return {
        "url_type": "GENERAL_WEBSITE",
        "category": "General Website / Portal",
        "is_payment_related": False,
        "domain": host,
        "path": path,
    }
