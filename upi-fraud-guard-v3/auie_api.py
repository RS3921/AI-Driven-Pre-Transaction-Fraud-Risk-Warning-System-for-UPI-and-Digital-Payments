"""
FastAPI APIRouter for Adaptive URL Intelligence Engine (AUIE).

Provides endpoints for:
- URL Reputation Lookup & Analysis Details
- Intelligence Provider Status & Health Monitoring
- Background Feed Synchronization Status
- Trusted Domain Management & Allowlisting
- Analyst False-Positive Feedback Reporting & Review Workflow
"""
from __future__ import annotations

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from api.security import current_user_id, current_user_role, require_role
from cti_database import cti_db
from url_qr_module.auie_bot import auie_bot
from url_qr_module.auie_engine import auie_engine
from url_qr_module.trusted_domains import trusted_domain_manager

router = APIRouter(prefix="/api/auie", tags=["Adaptive URL Intelligence Engine"])


class TrustedDomainRequest(BaseModel):
    domain: str = Field(..., max_length=253)
    category: str = Field(default="Legitimate Domain", max_length=100)
    allow_subdomains: bool = True
    requires_path_check: bool = False
    review_notes: str = Field(default="", max_length=1000)


class FeedbackReportRequest(BaseModel):
    url_or_domain: str = Field(..., max_length=1000)
    reported_verdict: str = Field(..., max_length=50)
    claimed_verdict: str = Field(..., max_length=50)
    reason: str = Field(..., max_length=1000)


class FeedbackReviewRequest(BaseModel):
    action: str = Field(..., pattern="^(APPROVED|REJECTED)$")
    review_notes: str = Field(default="", max_length=1000)


@router.get("/reputation")
def get_url_reputation(
    url: str = Query(..., min_length=1, max_length=2000),
    bypass_cache: bool = Query(default=False),
    user_id: str = Depends(current_user_id),
):
    """Real-time AUIE URL reputation lookup across 4 states (CONFIRMED_MALICIOUS, SUSPICIOUS, UNKNOWN, KNOWN_BENIGN)."""
    return auie_engine.evaluate_url(url, bypass_cache=bypass_cache, user_id=user_id)


@router.get("/providers")
def get_provider_statuses(user_id: str = Depends(current_user_id)):
    """Returns the operational status, latency, and configuration of intelligence providers."""
    return cti_db.get_provider_statuses()


@router.get("/health")
def get_auie_health(user_id: str = Depends(current_user_id)):
    """Returns background threat intelligence feed health and last successful update timestamps."""
    return {
        "feed_health": auie_bot.get_feed_health(),
        "providers": cti_db.get_provider_statuses(),
    }


@router.get("/trusted-domains")
def list_trusted_domains(user_id: str = Depends(current_user_id)):
    """Returns the list of verified trusted domains and allowlist metadata."""
    return cti_db.get_trusted_domains()


@router.post("/trusted-domains")
def add_trusted_domain(
    req: TrustedDomainRequest,
    user_id: str = Depends(current_user_id),
    role: str = Depends(require_role(["super_admin", "fraud_analyst"])),
):
    """Adds or updates a verified trusted domain entry."""
    success = cti_db.add_trusted_domain(
        domain=req.domain,
        category=req.category,
        allow_subdomains=req.allow_subdomains,
        requires_path_check=req.requires_path_check,
        added_by=f"{user_id} ({role})",
        notes=req.review_notes,
    )
    trusted_domain_manager.invalidate_cache()
    return {"status": "Success", "domain": req.domain.strip().lower()}


@router.delete("/trusted-domains/{domain}")
def remove_trusted_domain(
    domain: str,
    role: str = Depends(require_role(["super_admin"])),
):
    """Removes a domain from the trusted domain allowlist."""
    deleted = cti_db.remove_trusted_domain(domain)
    if not deleted:
        raise HTTPException(status_code=404, detail="Domain not found in trusted domain list")
    trusted_domain_manager.invalidate_cache()
    return {"status": "Removed", "domain": domain.strip().lower()}


@router.post("/feedback")
def submit_false_positive_feedback(
    req: FeedbackReportRequest,
    reporter_id: str = Depends(current_user_id),
):
    """Submits a false-positive or false-negative report for analyst review."""
    feedback_id = cti_db.add_false_positive_feedback(
        url_or_domain=req.url_or_domain,
        reported_verdict=req.reported_verdict,
        claimed_verdict=req.claimed_verdict,
        reporter_id=reporter_id,
        reason=req.reason,
    )
    return {"status": "Reported", "feedback_id": feedback_id}


@router.get("/feedback")
def list_feedback_reports(
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    role: str = Depends(require_role(["super_admin", "fraud_analyst"])),
):
    """Lists reported false-positive feedback items for analyst triage."""
    return cti_db.get_false_positive_feedback(status=status, limit=limit)


@router.post("/feedback/{feedback_id}/review")
def review_feedback_report(
    feedback_id: int,
    req: FeedbackReviewRequest,
    reviewer_id: str = Depends(current_user_id),
    role: str = Depends(require_role(["super_admin", "fraud_analyst"])),
):
    """Analyst review workflow for false-positive feedback."""
    updated = cti_db.review_false_positive_feedback(
        feedback_id=feedback_id,
        reviewer_id=f"{reviewer_id} ({role})",
        new_status=req.action,
        notes=req.review_notes,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Feedback report not found")
    return {"status": "Updated", "feedback_id": feedback_id, "action": req.action}


@router.get("/history")
def get_analysis_history(
    limit: int = Query(default=50, ge=1, le=500),
    user_id: str = Depends(current_user_id),
):
    """Returns recent AUIE analysis history logs."""
    return cti_db.get_auie_analysis_history(limit=limit)
