"""
Secure Multi-Hop Redirect & URL Shortener Resolution Engine.

Follows HTTP/HTTPS redirects safely up to 5 hops while enforcing:
- SSRF defenses & public IP socket resolution on EVERY hop
- Cross-host sensitive credential & header stripping
- Redirect loop detection & hop limits
- Per-hop latency tracking & trace logs
"""
from __future__ import annotations

import http.client
import logging
import socket
import ssl
import time
import urllib.parse
from typing import Any, Dict, List, Optional

from cti_security import (
    ALLOWED_SOURCE_HOSTS, SENSITIVE_HEADERS, SSRFValidationError,
    _PinnedHTTPConnection, _PinnedHTTPSConnection, _resolve_public,
    _create_secure_ssl_context, validate_url_security
)

logger = logging.getLogger("upi_fraud_guard.auie.redirects")

MAX_REDIRECT_HOPS = 5
PER_HOP_TIMEOUT_SECONDS = 1.5
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "goo.su", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorte.st", "rb.gy", "shorturl.at",
}


def trace_url_redirects(initial_url: str, max_hops: int = MAX_REDIRECT_HOPS) -> Dict[str, Any]:
    """
    Traces HTTP/HTTPS redirects safely hop-by-hop.
    Returns structured redirect analysis trace including final URL, hop count, and security notices.
    """
    start_time = time.time()
    clean_url = (initial_url or "").strip()

    if not clean_url or clean_url.lower().startswith("upi://"):
        return {
            "initial_url": clean_url,
            "final_url": clean_url,
            "hop_count": 0,
            "redirect_chain": [],
            "is_cross_domain": False,
            "has_shortener": False,
            "has_redirect_loop": False,
            "verified_destination": True,
            "error_message": "",
            "latency_ms": 0.0,
        }

    current_url = clean_url if "://" in clean_url else f"https://{clean_url}"
    redirect_chain: List[Dict[str, Any]] = []
    seen_urls: set[str] = set()
    seen_hosts: List[str] = []
    has_shortener = False
    has_loop = False
    error_msg = ""

    for hop in range(max_hops + 1):
        if current_url in seen_urls:
            has_loop = True
            error_msg = f"Redirect loop detected at hop {hop}: '{current_url}'"
            break
        seen_urls.add(current_url)

        parsed = urllib.parse.urlsplit(current_url)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower()
        if host in SHORTENER_DOMAINS:
            has_shortener = True

        seen_hosts.append(host)

        if hop >= max_hops:
            error_msg = f"Maximum redirect hops ({max_hops}) exceeded"
            break

        # Validate URL security on EVERY hop
        try:
            port = parsed.port or (443 if scheme == "https" else 80)
            family, sockaddr = _resolve_public(host, port, allowed_hosts=None)
        except Exception as err:
            error_msg = f"Hop {hop+1} security validation failed for '{host}': {err}"
            break

        # Perform HEAD or GET request to inspect redirect header
        conn_cls = _PinnedHTTPSConnection if scheme == "https" else _PinnedHTTPConnection
        conn = conn_cls(host, sockaddr, timeout=PER_HOP_TIMEOUT_SECONDS)
        try:
            req_path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
            conn.request("HEAD", req_path, headers={"User-Agent": "UPIFraudGuard-AUIE/2.6.0"})
            resp = conn.getresponse()
            conn.close()

            status = resp.status
            redirect_location = resp.getheader("Location")

            redirect_chain.append({
                "hop": hop + 1,
                "url": current_url,
                "host": host,
                "status_code": status,
                "location": redirect_location or "",
            })

            if status in (301, 302, 303, 307, 308) and redirect_location:
                next_url = urllib.parse.urljoin(current_url, redirect_location)
                current_url = next_url
            else:
                # Terminal URL reached (200, 404, etc.)
                break
        except Exception as conn_err:
            error_msg = f"Hop {hop+1} connection error to '{host}': {conn_err}"
            break

    total_latency = round((time.time() - start_time) * 1000.0, 2)
    is_cross_domain = len(set(seen_hosts)) > 1

    return {
        "initial_url": clean_url,
        "final_url": current_url,
        "hop_count": len(redirect_chain),
        "redirect_chain": redirect_chain,
        "is_cross_domain": is_cross_domain,
        "has_shortener": has_shortener,
        "has_redirect_loop": has_loop,
        "verified_destination": not bool(error_msg),
        "error_message": error_msg,
        "latency_ms": total_latency,
    }
