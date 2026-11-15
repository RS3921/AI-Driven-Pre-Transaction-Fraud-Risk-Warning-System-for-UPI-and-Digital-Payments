"""
Structured Risk Explanation & Human-Readable Advisory Engine for AUIE.

Generates comprehensive, defensible, evidence-based explanations distinguishing:
- Positive security indicators
- Negative risk indicators
- CTI threat matches
- Redirect trace & shortener resolution findings
- Static content & UPI PIN threat findings
- Unavailable checks & human-readable advisory summaries
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("upi_fraud_guard.auie.explanations")


def generate_structured_explanation(
    url_type_info: Dict[str, Any],
    reputation_state: str,
    risk_score: float,
    confidence_score: float,
    domain: str,
    raw_url: str,
    reasons: List[str],
    sources_evidence: List[Any],
    trusted_info: Optional[Dict[str, Any]] = None,
    redirect_info: Optional[Dict[str, Any]] = None,
    content_info: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Builds a complete, defensible explanation dictionary compliant with AUIE Phase 5 specifications.
    """
    url_type = url_type_info.get("url_type", "UNKNOWN_URL_TYPE")
    category_desc = url_type_info.get("category", "Website Link")

    positive_indicators: List[Dict[str, Any]] = []
    negative_indicators: List[Dict[str, Any]] = []
    threat_intel_matches: List[Dict[str, Any]] = []
    unavailable_checks: List[str] = []

    # 1. Evaluate Trusted Domain Evidence
    if trusted_info:
        positive_indicators.append({
            "name": f"Verified Domain Allowlist ({trusted_info.get('category', 'Legitimate Domain')})",
            "finding": f"Domain '{trusted_info.get('matched_domain')}' is a recognized legitimate portal in official registries.",
            "why_it_matters": "Official verified banking, payment gateway, and government domains carry a low baseline probability of malicious intent.",
            "source": trusted_info.get("source", "trusted_domain_manager"),
            "type": "confirmed",
            "contribution": "decreased_risk",
        })

    # 2. Evaluate CTI Threat Intel Evidence
    for ev in sources_evidence:
        if isinstance(ev, dict) and ev.get("type") == "verified_cti":
            threat_intel_matches.append(ev)
            negative_indicators.append({
                "name": f"Verified Threat Intel Match ({ev.get('source_name')})",
                "finding": f"Indicator matched active threat feed record for '{ev.get('matched_value')}'",
                "why_it_matters": "CRITICAL RISK: Active threat intelligence feeds confirmed this target is associated with phishing, malware, or scam operations.",
                "source": ev.get("source_name", "cti_matcher"),
                "type": "confirmed",
                "contribution": "increased_risk_critical",
            })
        elif isinstance(ev, dict) and ev.get("status") == "ACTIVE" and ev.get("matched"):
            negative_indicators.append({
                "name": f"External Provider Threat Flag ({ev.get('provider_name')})",
                "finding": ev.get("details", "External provider flagged link as threat"),
                "why_it_matters": "Commercial reputation providers reported malicious or suspicious activity for this target.",
                "source": ev.get("provider_name", "provider"),
                "type": "confirmed",
                "contribution": "increased_risk_high",
            })
        elif isinstance(ev, dict) and ev.get("status") in ("UNCONFIGURED", "FAILED"):
            p_name = ev.get("provider_name", "Provider")
            unavailable_checks.append(f"{p_name}: {ev.get('details', 'Check unavailable')}")

    # 3. Evaluate Content Findings
    if content_info and content_info.get("inspected"):
        for f in content_info.get("findings", []):
            if f.get("contribution") in ("critical_risk_boost", "high_risk_boost"):
                negative_indicators.append(f)
    elif content_info and not content_info.get("inspected"):
        unavailable_checks.append("Static website HTML inspection could not be completed.")

    # 4. Evaluate Redirect Findings
    if redirect_info:
        if redirect_info.get("has_shortener"):
            negative_indicators.append({
                "name": "Link Shortener Obfuscation",
                "finding": f"Link uses a URL shortener service ({domain}) which hides its true final destination",
                "why_it_matters": "URL shorteners are frequently used in SMS/chat scams to bypass domain filters and hide malicious destination hosts.",
                "source": "redirect_analyzer",
                "type": "heuristic",
                "contribution": "increased_risk_medium",
            })
        if redirect_info.get("has_redirect_loop"):
            negative_indicators.append({
                "name": "Redirect Loop Detected",
                "finding": redirect_info.get("error_message", "Redirect loop encountered"),
                "why_it_matters": "Redirect loops indicate suspicious cloaking or server configuration errors.",
                "source": "redirect_analyzer",
                "type": "heuristic",
                "contribution": "increased_risk_medium",
            })
        if not redirect_info.get("verified_destination") and redirect_info.get("error_message"):
            unavailable_checks.append(f"Redirect resolution trace: {redirect_info.get('error_message')}")

    # 5. Evaluate General Reasons as Heuristics
    for r in reasons:
        if "HTTPS" in r and "not" in r:
            negative_indicators.append({
                "name": "Insecure Connection (HTTP)",
                "finding": r,
                "why_it_matters": "Unencrypted HTTP connections can be intercepted and lack transport-layer authentication.",
                "source": "url_structure_analyzer",
                "type": "heuristic",
                "contribution": "increased_risk_low",
            })
        elif "IP address" in r:
            negative_indicators.append({
                "name": "Raw IP Address Host",
                "finding": r,
                "why_it_matters": "Legitimate businesses use domain names rather than raw IP addresses for web portals.",
                "source": "url_structure_analyzer",
                "type": "heuristic",
                "contribution": "increased_risk_medium",
            })

    # Deduplicate indicators
    positive_indicators = list({i["name"]: i for i in positive_indicators}.values())
    negative_indicators = list({i["name"]: i for i in negative_indicators}.values())

    # 6. Determine Risk Tier & Recommended Action
    if risk_score >= 0.85 or reputation_state == "CONFIRMED_MALICIOUS":
        risk_tier = "Critical"
        recommended_action = "CRITICAL WARNING: Do not open this link or proceed with payment. This URL is a confirmed threat."
    elif risk_score >= 0.65 or reputation_state == "SUSPICIOUS":
        risk_tier = "High"
        recommended_action = "HIGH RISK: Proceed with extreme caution. Verify the payee or website identity through official channels before sharing information."
    elif risk_score >= 0.30:
        risk_tier = "Medium"
        recommended_action = "MEDIUM RISK: Review website details and confirm payee identity in your official payment app before approving."
    else:
        risk_tier = "Low"
        recommended_action = "LOW RISK: Proceed with normal payment precautions."

    # 7. Build Human-Readable Summary Paragraph
    if reputation_state == "CONFIRMED_MALICIOUS":
        human_explanation = f"The submitted URL '{domain}' matches confirmed malicious threat intelligence indicators. Do not proceed or share personal or payment information."
    elif reputation_state == "KNOWN_BENIGN":
        human_explanation = f"The submitted URL belongs to the verified official portal for '{domain}' ({trusted_info.get('category', 'Legitimate Domain') if trusted_info else 'Trusted Portal'}). No known malicious threat indicators were found."
    elif reputation_state == "SUSPICIOUS":
        human_explanation = f"The URL '{domain}' contains risk indicators (such as sensitive keyword lures, shortener obfuscation, or unverified forms). Exercise caution before interacting."
    else:
        human_explanation = f"The domain '{domain}' is not present in threat intelligence or verified trusted domain registries. There is insufficient evidence to confirm whether this URL is safe."

    return {
        "url_type": url_type,
        "category_description": category_desc,
        "reputation_state": reputation_state,
        "risk_score": round(risk_score, 3),
        "confidence_score": round(confidence_score, 2),
        "risk_tier": risk_tier,
        "recommended_action": recommended_action,
        "human_readable_explanation": human_explanation,
        "positive_indicators": positive_indicators,
        "negative_indicators": negative_indicators,
        "threat_intel_matches": threat_intel_matches,
        "website_reputation": {
            "domain": domain,
            "is_trusted": bool(trusted_info),
            "category": trusted_info.get("category") if trusted_info else "Unindexed Domain",
        },
        "redirect_analysis": redirect_info or {},
        "content_findings": content_info.get("findings", []) if content_info else [],
        "unavailable_checks": unavailable_checks,
    }
