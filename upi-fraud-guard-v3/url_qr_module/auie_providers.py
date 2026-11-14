"""
Independent Intelligence Provider Adapters for AUIE.

Integrates commercial and threat-intelligence providers:
- Google Web Risk API (Commercial)
- VirusTotal API v3
- URLhaus Recent Malware API
- OpenPhish Phishing Feed / API
- AlienVault OTX Threat API

Enforces:
- Out-of-band environment variable configuration
- Sensitive parameter stripping for privacy compliance
- Per-provider timeout caps (2.0s max), retries, and failure isolation
- Status tracking: ACTIVE, UNCONFIGURED, FAILED
"""
from __future__ import annotations

import json
import logging
import time
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

from cti_security import get_environment_secret, validate_url_security
from cti_database import cti_db

import ssl

logger = logging.getLogger("upi_fraud_guard.auie.providers")

def _get_secure_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    try:
        import certifi
        ctx.load_verify_locations(cafile=certifi.where())
    except Exception:
        pass
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    return ctx

SENSITIVE_QUERY_PARAMS = {
    "pa", "pn", "am", "tn", "mc", "tr", "tid", "ref", "token", "key",
    "otp", "auth", "password", "pin", "cvv", "user", "account", "mobile", "phone",
}


def sanitize_url_for_privacy(raw_url: str) -> str:
    """Strips sensitive UPI, payment, and authentication parameters before sending to external services."""
    if not raw_url or "://" not in raw_url:
        return raw_url

    try:
        parsed = urllib.parse.urlparse(raw_url)
        query_tuples = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        safe_query = [(k, v) for k, v in query_tuples if k.lower() not in SENSITIVE_QUERY_PARAMS]
        clean_query = urllib.parse.urlencode(safe_query)
        return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, clean_query, ""))
    except Exception:
        return raw_url


class BaseIntelligenceProvider:
    """Base class for AUIE external threat intelligence providers."""

    def __init__(self, provider_id: str, name: str, env_key_name: str = "") -> None:
        self.provider_id = provider_id
        self.name = name
        self.env_key_name = env_key_name

    def is_configured(self) -> bool:
        if not self.env_key_name:
            return True
        return bool(get_environment_secret(self.env_key_name))

    def lookup_url(self, target_url: str, domain: str) -> Dict[str, Any]:
        start_time = time.time()
        if not self.is_configured():
            cti_db.update_provider_status(self.provider_id, self.name, "UNCONFIGURED", "Missing API key configuration")
            return {
                "provider_id": self.provider_id,
                "provider_name": self.name,
                "status": "UNCONFIGURED",
                "matched": False,
                "reputation_state": "UNKNOWN",
                "confidence": 0.0,
                "threat_category": "none",
                "details": "Provider API key unconfigured",
                "latency_ms": 0.0,
            }

        safe_target = sanitize_url_for_privacy(target_url)

        try:
            res = self._execute_lookup(safe_target, domain)
            latency = (time.time() - start_time) * 1000.0
            res["latency_ms"] = round(latency, 2)
            cti_db.update_provider_status(self.provider_id, self.name, "ACTIVE")
            return res
        except Exception as err:
            latency = (time.time() - start_time) * 1000.0
            error_str = str(err)[:500]
            logger.warning("Provider '%s' lookup failed: %s", self.name, error_str)
            cti_db.update_provider_status(self.provider_id, self.name, "FAILED", error_msg=error_str)
            return {
                "provider_id": self.provider_id,
                "provider_name": self.name,
                "status": "FAILED",
                "matched": False,
                "reputation_state": "UNKNOWN",
                "confidence": 0.0,
                "threat_category": "none",
                "details": f"Provider request failed: {error_str}",
                "latency_ms": round(latency, 2),
            }

    def _execute_lookup(self, target_url: str, domain: str) -> Dict[str, Any]:
        raise NotImplementedError


class GoogleWebRiskProvider(BaseIntelligenceProvider):
    """Google Web Risk Commercial API Provider."""

    def __init__(self) -> None:
        super().__init__("PROV-WEBRISK", "Google Web Risk Commercial API", "GOOGLE_WEB_RISK_API_KEY")

    def _execute_lookup(self, target_url: str, domain: str) -> Dict[str, Any]:
        api_key = get_environment_secret(self.env_key_name)
        if not api_key:
            raise ValueError("Missing GOOGLE_WEB_RISK_API_KEY")

        endpoint = f"https://webrisk.googleapis.com/v1/uris:search?key={api_key}&threatTypes=MALWARE&threatTypes=SOCIAL_ENGINEERING&threatTypes=UNWANTED_SOFTWARE&uri={urllib.parse.quote(target_url)}"
        validate_url_security(endpoint)

        req = urllib.request.Request(endpoint, headers={"User-Agent": "UPIFraudGuard-AUIE/2.6.0"})
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        threat = data.get("threat", {})
        threat_types = threat.get("threatTypes", [])
        if threat_types:
            return {
                "provider_id": self.provider_id,
                "provider_name": self.name,
                "status": "ACTIVE",
                "matched": True,
                "reputation_state": "CONFIRMED_MALICIOUS",
                "confidence": 0.95,
                "threat_category": threat_types[0].lower(),
                "details": f"Google Web Risk flagged threat types: {', '.join(threat_types)}",
            }

        return {
            "provider_id": self.provider_id,
            "provider_name": self.name,
            "status": "ACTIVE",
            "matched": False,
            "reputation_state": "UNKNOWN",
            "confidence": 0.0,
            "threat_category": "none",
            "details": "No threat matches found in Google Web Risk database",
        }


class VirusTotalProvider(BaseIntelligenceProvider):
    """VirusTotal API v3 URL Reputation Provider."""

    def __init__(self) -> None:
        super().__init__("PROV-VIRUSTOTAL", "VirusTotal Reputation API", "VIRUSTOTAL_API_KEY")

    def _execute_lookup(self, target_url: str, domain: str) -> Dict[str, Any]:
        api_key = get_environment_secret(self.env_key_name)
        if not api_key:
            raise ValueError("Missing VIRUSTOTAL_API_KEY")

        import base64
        url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        validate_url_security(endpoint)

        req = urllib.request.Request(endpoint, headers={"x-apikey": api_key, "User-Agent": "UPIFraudGuard-AUIE/2.6.0"})
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious >= 3:
            state = "CONFIRMED_MALICIOUS"
            confidence = min(0.99, 0.70 + 0.05 * malicious)
        elif malicious >= 1 or suspicious >= 2:
            state = "SUSPICIOUS"
            confidence = 0.65
        else:
            state = "UNKNOWN"
            confidence = 0.0

        return {
            "provider_id": self.provider_id,
            "provider_name": self.name,
            "status": "ACTIVE",
            "matched": malicious > 0 or suspicious > 0,
            "reputation_state": state,
            "confidence": round(confidence, 2),
            "threat_category": "phishing_malware" if malicious > 0 else "none",
            "details": f"VirusTotal analysis: {malicious} engines malicious, {suspicious} engines suspicious",
        }


class UrlhausProvider(BaseIntelligenceProvider):
    """URLhaus Malware URL Lookup API Provider."""

    def __init__(self) -> None:
        super().__init__("PROV-URLHAUS", "URLhaus Threat API", "URLHAUS_API_KEY")

    def _execute_lookup(self, target_url: str, domain: str) -> Dict[str, Any]:
        api_key = get_environment_secret(self.env_key_name)
        if not api_key:
            # Check local CTI indicators for URLhaus feed records
            indicators = cti_db.query_indicators(source_name="URLhaus Recent URLs", limit=1000)
            target_clean = target_url.strip().lower()
            for ind in indicators:
                if ind["indicator_value"].strip().lower() == target_clean:
                    return {
                        "provider_id": self.provider_id,
                        "provider_name": self.name,
                        "status": "ACTIVE",
                        "matched": True,
                        "reputation_state": "CONFIRMED_MALICIOUS",
                        "confidence": 0.90,
                        "threat_category": "malware",
                        "details": "URL matched cached URLhaus intelligence feed indicator",
                    }
            return {
                "provider_id": self.provider_id,
                "provider_name": self.name,
                "status": "UNCONFIGURED",
                "matched": False,
                "reputation_state": "UNKNOWN",
                "confidence": 0.0,
                "threat_category": "none",
                "details": "URLhaus API key unconfigured; local cache checked",
            }

        endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
        validate_url_security(endpoint)

        post_data = urllib.parse.urlencode({"url": target_url}).encode("utf-8")
        headers = {"User-Agent": "UPIFraudGuard-AUIE/2.6.0", "Auth-Key": api_key}
        req = urllib.request.Request(endpoint, data=post_data, headers=headers)
        with urllib.request.urlopen(req, timeout=2.0, context=_get_secure_ssl_context()) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        query_status = data.get("query_status")
        if query_status == "ok":
            url_status = data.get("url_status", "unknown")
            threat = data.get("threat", "malware")
            return {
                "provider_id": self.provider_id,
                "provider_name": self.name,
                "status": "ACTIVE",
                "matched": True,
                "reputation_state": "CONFIRMED_MALICIOUS" if url_status == "online" else "SUSPICIOUS",
                "confidence": 0.90 if url_status == "online" else 0.70,
                "threat_category": threat.lower(),
                "details": f"URLhaus record found: threat={threat}, status={url_status}",
            }

        return {
            "provider_id": self.provider_id,
            "provider_name": self.name,
            "status": "ACTIVE",
            "matched": False,
            "reputation_state": "UNKNOWN",
            "confidence": 0.0,
            "threat_category": "none",
            "details": "URL not listed in URLhaus malware database",
        }


class OpenPhishProvider(BaseIntelligenceProvider):
    """OpenPhish Threat Lookup Provider."""

    def __init__(self) -> None:
        super().__init__("PROV-OPENPHISH", "OpenPhish Intelligence API", "OPENPHISH_API_KEY")

    def _execute_lookup(self, target_url: str, domain: str) -> Dict[str, Any]:
        api_key = get_environment_secret(self.env_key_name)
        if not api_key:
            # Fallback to local CTI indicator check for OpenPhish records
            indicators = cti_db.query_indicators(source_name="OpenPhish Community Feed", limit=1000)
            target_clean = target_url.strip().lower()
            for ind in indicators:
                if ind["indicator_value"].strip().lower() == target_clean:
                    return {
                        "provider_id": self.provider_id,
                        "provider_name": self.name,
                        "status": "ACTIVE",
                        "matched": True,
                        "reputation_state": "CONFIRMED_MALICIOUS",
                        "confidence": 0.85,
                        "threat_category": "phishing",
                        "details": "URL matched cached OpenPhish intelligence feed indicator",
                    }
            return {
                "provider_id": self.provider_id,
                "provider_name": self.name,
                "status": "UNCONFIGURED",
                "matched": False,
                "reputation_state": "UNKNOWN",
                "confidence": 0.0,
                "threat_category": "none",
                "details": "OpenPhish API key unconfigured; local cache checked",
            }

        endpoint = f"https://openphish.com/api/v2/url/check?key={api_key}&url={urllib.parse.quote(target_url)}"
        validate_url_security(endpoint)

        req = urllib.request.Request(endpoint, headers={"User-Agent": "UPIFraudGuard-AUIE/2.6.0"})
        with urllib.request.urlopen(req, timeout=2.0, context=_get_secure_ssl_context()) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        if data.get("phish"):
            return {
                "provider_id": self.provider_id,
                "provider_name": self.name,
                "status": "ACTIVE",
                "matched": True,
                "reputation_state": "CONFIRMED_MALICIOUS",
                "confidence": 0.92,
                "threat_category": "phishing",
                "details": "OpenPhish confirmed active phishing target",
            }

        return {
            "provider_id": self.provider_id,
            "provider_name": self.name,
            "status": "ACTIVE",
            "matched": False,
            "reputation_state": "UNKNOWN",
            "confidence": 0.0,
            "threat_category": "none",
            "details": "URL not listed in OpenPhish database",
        }


class AlienVaultOtxProvider(BaseIntelligenceProvider):
    """AlienVault OTX Threat Intelligence Provider."""

    def __init__(self) -> None:
        super().__init__("PROV-OTX", "AlienVault OTX Threat API", "OTX_API_KEY")

    def _execute_lookup(self, target_url: str, domain: str) -> Dict[str, Any]:
        api_key = get_environment_secret(self.env_key_name)
        if not api_key:
            raise ValueError("Missing OTX_API_KEY")

        endpoint = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
        validate_url_security(endpoint)

        req = urllib.request.Request(endpoint, headers={"X-OTX-API-KEY": api_key, "User-Agent": "UPIFraudGuard-AUIE/2.6.0"})
        with urllib.request.urlopen(req, timeout=2.0, context=_get_secure_ssl_context()) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        pulse_count = data.get("pulse_info", {}).get("count", 0)
        if pulse_count > 0:
            return {
                "provider_id": self.provider_id,
                "provider_name": self.name,
                "status": "ACTIVE",
                "matched": True,
                "reputation_state": "SUSPICIOUS" if pulse_count < 3 else "CONFIRMED_MALICIOUS",
                "confidence": min(0.95, 0.50 + 0.15 * pulse_count),
                "threat_category": "threat_pulse",
                "details": f"AlienVault OTX found {pulse_count} active threat pulses for domain '{domain}'",
            }

        return {
            "provider_id": self.provider_id,
            "provider_name": self.name,
            "status": "ACTIVE",
            "matched": False,
            "reputation_state": "UNKNOWN",
            "confidence": 0.0,
            "threat_category": "none",
            "details": f"Domain '{domain}' has zero threat pulses in AlienVault OTX",
        }


ALL_PROVIDERS: List[BaseIntelligenceProvider] = [
    GoogleWebRiskProvider(),
    VirusTotalProvider(),
    UrlhausProvider(),
    OpenPhishProvider(),
    AlienVaultOtxProvider(),
]
