"""
Adaptive URL Intelligence Engine (AUIE) Core Subsystem — Enhanced Version.

Combines:
- URL Type & Intent Classification
- 4-State Reputation Classification (CONFIRMED_MALICIOUS, SUSPICIOUS, UNKNOWN, KNOWN_BENIGN)
- Verified Domain Allowlisting (Trusted Domain Manager)
- Local Verified CTI Threat Intelligence Matches
- Multi-Source External Provider Lookups (Web Risk, VirusTotal, URLhaus, OpenPhish, OTX)
- Secure Multi-Hop Redirect Trace & Shortener Resolution
- Static Website Content & UPI PIN Threat Inspection
- Structured Risk Explanation & Evidence Attribution Engine
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import logging
import re
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from cti_database import cti_db
from cti_matcher import cti_matcher
from cti_normalization import intelligence_normalizer
from url_qr_module.auie_providers import ALL_PROVIDERS, BaseIntelligenceProvider
from url_qr_module.content_inspector import inspect_website_content
from url_qr_module.explanation_engine import generate_structured_explanation
from url_qr_module.redirect_analyzer import trace_url_redirects
from url_qr_module.trusted_domains import trusted_domain_manager
from url_qr_module.url_type_identifier import classify_url_type

logger = logging.getLogger("upi_fraud_guard.auie.engine")

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "goo.su", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorte.st", "rb.gy", "shorturl.at",
}
SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "info", "online", "site", "live", "work",
    "loan", "win", "gq", "tk", "ml", "cf", "icu",
}
SUSPICIOUS_KEYWORDS = {
    "verify", "login", "update", "secure", "kyc", "reward", "claim", "bonus",
    "wallet", "upi", "bank", "account", "password", "gift", "refund", "suspend", "unlock",
}


class AUIEEngine:
    """Adaptive URL Intelligence Engine for pre-transaction risk scoring and classification."""

    def __init__(self) -> None:
        self.providers: List[BaseIntelligenceProvider] = ALL_PROVIDERS
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=5, thread_name_prefix="AUIE-Lookup")

    @staticmethod
    def canonicalize_url(raw_url: str) -> Tuple[str, str, str]:
        """Canonicalizes URL safely, returning (canonical_url, domain, url_hash)."""
        clean = (raw_url or "").strip()
        candidate = clean if "://" in clean else f"https://{clean}"
        parsed = urllib.parse.urlparse(candidate)
        host = (parsed.hostname or "").lower()

        ascii_host, unicode_host, _ = trusted_domain_manager.normalize_hostname(host)
        canonical = intelligence_normalizer.canonicalize_url(candidate)
        url_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return canonical, ascii_host, url_hash

    def evaluate_url(self, raw_url: str, bypass_cache: bool = False, user_id: str = "system") -> Dict[str, Any]:
        """
        Main entry point for AUIE URL reputation analysis.
        Returns structured 4-state classification, risk score, reasons, and evidence.
        """
        start_time = time.time()
        raw_url = (raw_url or "").strip()
        if not raw_url:
            type_info = classify_url_type("")
            explanation = generate_structured_explanation(
                type_info, "UNKNOWN", 0.0, 0.0, "", "", ["No URL provided for analysis"], []
            )
            return {
                "raw_url": "",
                "canonical_url": "",
                "domain": "",
                "reputation_state": "UNKNOWN",
                "risk_score": 0.0,
                "confidence_score": 0.0,
                "reasons": ["No URL provided for analysis"],
                "sources_evidence": [],
                "conflicting_evidence": [],
                "providers_consulted": [],
                "explanation": explanation,
                "cache_status": "HIT" if not bypass_cache else "BYPASS",
                "latency_ms": 0.0,
            }

        # 0. Identify URL Type & Intent
        type_info = classify_url_type(raw_url)

        canonical_url, domain, url_hash = self.canonicalize_url(raw_url)
        if not domain and type_info["url_type"] != "UPI_PAYMENT_LINK":
            explanation = generate_structured_explanation(
                type_info, "SUSPICIOUS", 0.72, 0.80, "", raw_url, ["Link format is invalid or missing a valid hostname"], []
            )
            return {
                "raw_url": raw_url,
                "canonical_url": canonical_url,
                "domain": "",
                "reputation_state": "SUSPICIOUS",
                "risk_score": 0.72,
                "confidence_score": 0.80,
                "reasons": ["Link format is invalid or missing a valid hostname"],
                "sources_evidence": [],
                "conflicting_evidence": [],
                "providers_consulted": [],
                "explanation": explanation,
                "cache_status": "INVALID",
                "latency_ms": round((time.time() - start_time) * 1000.0, 2),
            }

        # 1. Check live CTI Match
        cti_match = cti_matcher.match_url_or_domain(canonical_url)

        # 2. Check DB Cache if not bypassed
        if not bypass_cache:
            cached = cti_db.get_url_reputation(url_hash)
            if cached:
                state = cached["reputation_state"]
                if not (cti_match and state != "CONFIRMED_MALICIOUS"):
                    expires_at = cached.get("expires_at")
                    is_expired = False
                    if expires_at:
                        try:
                            exp_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                            if exp_dt.tzinfo is None:
                                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                            if datetime.now(timezone.utc) > exp_dt:
                                is_expired = True
                        except ValueError:
                            pass
                    if not is_expired:
                        latency = round((time.time() - start_time) * 1000.0, 2)
                        risk_score = 0.95 if state == "CONFIRMED_MALICIOUS" else 0.55 if state == "SUSPICIOUS" else 0.08 if state == "KNOWN_BENIGN" else 0.25
                        trusted_info = trusted_domain_manager.is_trusted(canonical_url)
                        explanation = generate_structured_explanation(
                            type_info, state, risk_score, cached["confidence_score"],
                            domain, raw_url, cached["reasons"], cached["sources_evidence"],
                            trusted_info=trusted_info
                        )
                        res = {
                            "raw_url": raw_url,
                            "canonical_url": canonical_url,
                            "domain": domain,
                            "reputation_state": state,
                            "risk_score": risk_score,
                            "confidence_score": cached["confidence_score"],
                            "reasons": cached["reasons"],
                            "sources_evidence": cached["sources_evidence"],
                            "conflicting_evidence": [],
                            "providers_consulted": [e.get("provider_name") for e in cached["sources_evidence"] if isinstance(e, dict) and e.get("provider_name")],
                            "explanation": explanation,
                            "cache_status": "HIT",
                            "latency_ms": latency,
                        }
                        if cti_match:
                            res["cti_match"] = cti_match
                        cti_db.add_auie_analysis_history(
                            raw_url, canonical_url, domain, state, risk_score, cached["reasons"],
                            res["providers_consulted"], True, latency, user_id
                        )
                        return res

        # 3. Trusted Domain Allowlist Check
        trusted_info = trusted_domain_manager.is_trusted(canonical_url)

        # 4. Redirect Analysis Trace
        redirect_info = trace_url_redirects(canonical_url)
        final_url = redirect_info.get("final_url", canonical_url)
        if final_url != canonical_url:
            _, final_domain, _ = self.canonicalize_url(final_url)
            if final_domain:
                domain = final_domain

        # 5. Static Content & UPI PIN Inspection
        content_info = inspect_website_content(final_url, domain)

        # 6. Lexical & Structural Feature Extraction
        parsed = urllib.parse.urlparse(canonical_url)
        path = f"{parsed.path}?{parsed.query}".lower()
        domain_parts = domain.split(".") if domain else []
        tld = domain_parts[-1] if len(domain_parts) >= 2 else ""

        lexical_reasons: List[str] = []
        is_https = parsed.scheme == "https"
        is_shortener = domain in SHORTENER_DOMAINS or redirect_info.get("has_shortener")
        is_raw_ip = bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", domain))
        is_idn = "xn--" in domain
        is_suspicious_tld = tld in SUSPICIOUS_TLDS
        lure_hits = sorted(w for w in SUSPICIOUS_KEYWORDS if w in f"{domain}{path}")

        if not is_https:
            lexical_reasons.append("Link does not use a secure HTTPS connection")
        if is_shortener:
            lexical_reasons.append("Link uses a URL shortener service which hides final destination")
        if is_raw_ip:
            lexical_reasons.append("Link uses a raw IP address instead of a domain name")
        if is_idn:
            lexical_reasons.append("Domain uses internationalized characters (IDN/Punycode)")
        if is_suspicious_tld:
            lexical_reasons.append(f"Domain uses throwaway or suspicious TLD (.{tld})")
        if lure_hits and not trusted_info:
            lexical_reasons.append(f"Link path contains sensitive lure keywords: {', '.join(lure_hits[:3])}")
        if len(canonical_url) > 120 and not trusted_info:
            lexical_reasons.append("Link has an unusually long URL path or query string")

        # 7. External Provider Asynchronous Queries
        provider_futures = [self.executor.submit(p.lookup_url, canonical_url, domain) for p in self.providers if p.is_configured()]
        provider_results: List[Dict[str, Any]] = []
        for future in concurrent.futures.as_completed(provider_futures):
            try:
                provider_results.append(future.result(timeout=2.5))
            except Exception as p_err:
                logger.warning("Provider lookup timed out or failed: %s", p_err)

        # 8. Aggregate Evidence & Determine Reputation State
        sources_evidence: List[Dict[str, Any]] = []
        conflicting_evidence: List[Dict[str, Any]] = []
        reasons: List[str] = []
        providers_consulted: List[str] = []

        malicious_evidence = False
        suspicious_evidence = False
        top_confidence = 0.0

        if cti_match:
            malicious_evidence = True
            top_confidence = max(top_confidence, 0.95)
            sources_evidence.append({
                "type": "verified_cti",
                "source_name": cti_match["source_name"],
                "matched_value": cti_match["matched_value"],
                "threat_category": cti_match["threat_category"],
                "confidence": 0.95,
            })
            reasons.append(f"VERIFIED THREAT INTEL: Domain/URL matches verified indicator in {cti_match['source_name']}")

        if content_info.get("has_upi_pin_threat"):
            malicious_evidence = True
            top_confidence = max(top_confidence, 0.95)
            reasons.append("CRITICAL SECURITY THREAT: Website or web form solicits entry of a UPI PIN or MPIN")

        for pres in provider_results:
            p_name = pres["provider_name"]
            providers_consulted.append(p_name)
            sources_evidence.append(pres)
            p_state = pres["reputation_state"]
            if p_state == "CONFIRMED_MALICIOUS":
                malicious_evidence = True
                top_confidence = max(top_confidence, pres["confidence"])
                reasons.append(f"EXTERNAL PROVIDER MATCH: {p_name} flagged URL as {pres['threat_category']}")
            elif p_state == "SUSPICIOUS":
                suspicious_evidence = True
                top_confidence = max(top_confidence, pres["confidence"])
                reasons.append(f"EXTERNAL PROVIDER SUSPICIOUS: {p_name} reported threat pulses")

        if content_info.get("has_impersonation"):
            suspicious_evidence = True
            reasons.append(f"BRAND IMPERSONATION WARNING: Page title claims {content_info.get('impersonated_brand')} branding, but domain is unverified")

        # 9. Apply Decision Matrix
        if malicious_evidence:
            state = "CONFIRMED_MALICIOUS"
            risk_score = max(0.88, top_confidence)
            confidence_score = top_confidence if top_confidence > 0 else 0.95
        elif trusted_info and not cti_match and not content_info.get("has_upi_pin_threat"):
            # Domain is explicitly trusted, and NO verified malicious CTI/provider/content threat exists
            state = "KNOWN_BENIGN"
            risk_score = 0.08
            confidence_score = 0.95
            reasons.append(f"VERIFIED TRUSTED DOMAIN: Belongs to recognized {trusted_info['category']} ({trusted_info['matched_domain']})")
            if lexical_reasons:
                conflicting_evidence.append({
                    "type": "heuristic_notice",
                    "details": f"Lexical flags present but overridden by trusted domain reputation: {', '.join(lexical_reasons)}",
                })
        elif lexical_reasons or suspicious_evidence:
            state = "SUSPICIOUS"
            risk_score = min(0.78, 0.35 + 0.12 * len(lexical_reasons) + (0.20 if suspicious_evidence else 0.0))
            confidence_score = max(0.65, top_confidence)
            reasons.extend(lexical_reasons)
        else:
            state = "UNKNOWN"
            risk_score = 0.25
            confidence_score = 0.50
            reasons.append("URL has no known threat indicators; domain reputation history is unindexed/unknown")

        reasons = list(dict.fromkeys(reasons))  # Deduplicate reasons while preserving order
        latency = round((time.time() - start_time) * 1000.0, 2)
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=6)).isoformat()

        # Build Structured Explanation
        explanation = generate_structured_explanation(
            url_type_info=type_info,
            reputation_state=state,
            risk_score=risk_score,
            confidence_score=confidence_score,
            domain=domain,
            raw_url=raw_url,
            reasons=reasons,
            sources_evidence=sources_evidence,
            trusted_info=trusted_info,
            redirect_info=redirect_info,
            content_info=content_info,
        )

        # 10. Persist Analysis Result to Cache & Audit Log
        cti_db.upsert_url_reputation(
            url_hash, canonical_url, domain, state, round(confidence_score, 2),
            reasons, sources_evidence, expires_at=expires_at
        )

        cti_db.add_auie_analysis_history(
            raw_url, canonical_url, domain, state, round(risk_score, 3), reasons,
            providers_consulted, False, latency, user_id
        )

        return {
            "raw_url": raw_url,
            "canonical_url": canonical_url,
            "domain": domain,
            "reputation_state": state,
            "risk_score": round(risk_score, 3),
            "confidence_score": round(confidence_score, 2),
            "reasons": reasons,
            "sources_evidence": sources_evidence,
            "conflicting_evidence": conflicting_evidence,
            "providers_consulted": providers_consulted,
            "explanation": explanation,
            "cache_status": "MISS",
            "latency_ms": latency,
        }


# Global engine instance
auie_engine = AUIEEngine()
