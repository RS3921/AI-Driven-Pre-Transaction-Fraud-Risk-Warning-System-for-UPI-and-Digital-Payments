"""Pinned-IP, bounded, allowlisted HTTP fetching for CTI sources."""
from __future__ import annotations

import http.client
import ipaddress
import logging
import os
import socket
import ssl
import urllib.parse
from typing import Any, Dict, Optional

logger = logging.getLogger("upi_fraud_guard.cti_security")

MAX_RESPONSE_BYTES = 5 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 10.0
MAX_REDIRECT_HOPS = 5
ALLOWED_SOURCE_HOSTS = {
    "www.cert-in.org.in",
    "www.npci.org.in",
    "rbi.org.in",
    "data.phishtank.com",
    "urlhaus-api.abuse.ch",
    "openphish.com",
    "www.cisa.gov",
    "raw.githubusercontent.com",
    "api.abuseipdb.com",
    "otx.alienvault.com",
}
SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "cookie", "key", "x-otx-api-key"}

class SSRFValidationError(Exception):
    """Raised when URL, resolved address, or redirect violates outbound policy."""

class PayloadTooLargeError(Exception):
    """Raised when a response exceeds the configured byte budget."""

class SourceFetchError(Exception):
    """Raised when an allowlisted source request fails."""

def _host_allowed(host: str, allowed_hosts: Optional[set[str]] = None) -> bool:
    allow = ALLOWED_SOURCE_HOSTS if allowed_hosts is None else allowed_hosts
    host = host.lower().rstrip(".")
    return host in allow

def _resolve_public(host: str, port: int, allowed_hosts: Optional[set[str]] = None) -> tuple[int, tuple]:
    clean = host.lower().strip().rstrip(".")
    if clean in {"localhost", "instance-data", "metadata.google.internal"}:
        raise SSRFValidationError(f"Local or metadata hostname is forbidden: {clean}")
    try:
        literal = ipaddress.ip_address(clean)
    except ValueError:
        literal = None
    if literal is not None:
        addresses = [(socket.AF_INET6 if literal.version == 6 else socket.AF_INET,
                      socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (str(literal), port))]
    else:
        if not _host_allowed(clean, allowed_hosts):
            raise SSRFValidationError(f"Host is not in the CTI source allowlist: {clean}")
        try:
            addresses = socket.getaddrinfo(clean, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
        except socket.gaierror as err:
            raise SSRFValidationError(f"DNS resolution failed for {clean}: {err}") from err
    if not addresses:
        raise SSRFValidationError(f"No addresses resolved for {clean}")
    # Reject the entire answer set if any result is non-public; connect to one of
    # these exact validated sockaddr values, never ask the HTTP client to resolve again.
    for family, _, _, _, sockaddr in addresses:
        ip = ipaddress.ip_address(sockaddr[0].split("%", 1)[0])
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if not ip.is_global:
            raise SSRFValidationError(f"Host {clean} resolved to non-public address {ip}")
    return addresses[0][0], addresses[0][4]

def validate_url_security(url: str, allowed_hosts: Optional[set[str]] = None) -> str:
    if not isinstance(url, str) or not url.strip():
        raise SSRFValidationError("URL must be a non-empty string")
    parsed = urllib.parse.urlsplit(url.strip())
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise SSRFValidationError("Only absolute HTTP(S) URLs with a hostname are permitted")
    if parsed.username or parsed.password or parsed.fragment:
        raise SSRFValidationError("Credentials and fragments are not permitted in source URLs")
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    _resolve_public(parsed.hostname, port, allowed_hosts)
    return url.strip()

class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, hostname: str, sockaddr: tuple, timeout: float):
        super().__init__(hostname, port=sockaddr[1], timeout=timeout)
        self._sockaddr = sockaddr
    def connect(self):
        self.sock = socket.create_connection(self._sockaddr, self.timeout, self.source_address)

def _create_secure_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    try:
        import certifi
        ctx.load_verify_locations(cafile=certifi.where())
    except Exception:
        pass
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    return ctx

class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname: str, sockaddr: tuple, timeout: float):
        super().__init__(hostname, port=sockaddr[1], timeout=timeout, context=_create_secure_ssl_context())
        self._sockaddr = sockaddr
    def connect(self):
        raw = socket.create_connection(self._sockaddr, self.timeout, self.source_address)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise

def fetch_secure_content(
    url: str,
    headers: Optional[Dict[str, str]] = None,
    method: str = "GET",
    params: Optional[Dict[str, Any]] = None,
    max_bytes: int = MAX_RESPONSE_BYTES,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    allowed_hosts: Optional[set[str]] = None,
) -> bytes:
    if max_bytes < 0 or timeout_seconds <= 0:
        raise ValueError("max_bytes must be non-negative and timeout_seconds must be positive")
    current_url = url.strip()
    original_headers = {str(k): str(v) for k, v in (headers or {}).items()}
    original_headers.setdefault("User-Agent", "UPIFraudGuard-CTIEngine/3.0.0")
    original_host = None
    for hop in range(MAX_REDIRECT_HOPS + 1):
        parsed = urllib.parse.urlsplit(current_url)
        validate_url_security(current_url, allowed_hosts)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        family, sockaddr = _resolve_public(host, port, allowed_hosts)
        if original_host is None:
            original_host = host.lower()
        request_headers = dict(original_headers)
        if host.lower() != original_host:
            request_headers = {k: v for k, v in request_headers.items() if k.lower() not in SENSITIVE_HEADERS}
        request_headers["Host"] = host if port in (80, 443) else f"{host}:{port}"
        target = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        connection_type = _PinnedHTTPSConnection if parsed.scheme.lower() == "https" else _PinnedHTTPConnection
        conn = connection_type(host, sockaddr, timeout_seconds)
        try:
            conn.request(method if hop == 0 else "GET", target, headers=request_headers)
            response = conn.getresponse()
            if response.status in (301, 302, 303, 307, 308):
                location = response.getheader("Location")
                response.close()
                conn.close()
                if not location:
                    raise SourceFetchError("Redirect response omitted Location")
                if hop >= MAX_REDIRECT_HOPS:
                    raise SSRFValidationError("Too many source redirects")
                current_url = urllib.parse.urljoin(current_url, location)
                continue
            if response.status < 200 or response.status >= 300:
                raise SourceFetchError(f"Source returned HTTP {response.status}")
            content_length = response.getheader("Content-Length")
            if content_length and content_length.isdigit() and int(content_length) > max_bytes:
                raise PayloadTooLargeError(f"Response Content-Length exceeds {max_bytes} bytes")
            body = bytearray()
            while True:
                chunk = response.read(min(65536, max_bytes + 1 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
                if len(body) > max_bytes:
                    raise PayloadTooLargeError(f"Response exceeded {max_bytes} bytes while streaming")
            return bytes(body)
        except (SSRFValidationError, PayloadTooLargeError, SourceFetchError):
            raise
        except (OSError, http.client.HTTPException, ssl.SSLError) as err:
            raise SourceFetchError(f"Source request failed: {err}") from err
        finally:
            conn.close()
    raise SSRFValidationError("Too many source redirects")

def get_environment_secret(key_name: str, default: str = "") -> str:
    return os.environ.get(key_name, "").strip() or default
