"""
Authenticated CTI REST API Module for UPI Fraud Guard.

Endpoints:
- GET  /api/intelligence/status
- GET  /api/intelligence/sources
- GET  /api/intelligence/indicators
- GET  /api/intelligence/indicators/{indicator_id}
- GET  /api/intelligence/fraud-patterns
- GET  /api/intelligence/collection-logs
- POST /api/intelligence/indicators/{indicator_id}/review
- GET  /api/intelligence/models
- GET  /api/intelligence/models/evaluations
- GET  /api/intelligence/models/monitoring
- GET  /api/intelligence/models/{model_id}
- POST /api/intelligence/models/train
- POST /api/intelligence/models/{model_id}/approve
- POST /api/intelligence/models/{model_id}/deploy
- POST /api/intelligence/models/{model_id}/rollback
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from api.security import current_user_id, require_role
from cti_database import cti_db
from cti_collector import cti_collector_worker
from cti_matcher import cti_matcher

router = APIRouter(prefix="/api/intelligence", tags=["Cyber Threat Intelligence"])


class IndicatorReviewRequest(BaseModel):
    new_status: str = Field(..., description="New verification status: Verified Malicious, Reported Unverified, Suspicious, Allowlisted, Expired")
    review_notes: str = Field(default="", max_length=1000)


class ModelTrainRequest(BaseModel):
    algorithm: str = Field(default="RandomForest", description="Algorithm: RandomForest, GradientBoosting, LogisticRegression")
    dataset_version: str = Field(default="v1.1.0")


@router.get("/status")
def get_cti_status(user_id: str = Depends(current_user_id)):
    """Returns overall CTI engine status, total indicators, active sources, and worker health."""
    sources = cti_db.get_sources()
    indicators = cti_db.query_indicators(limit=1_000_000)
    verified = [i for i in indicators if i["verification_status"] == "Verified Malicious"]
    suspicious = [i for i in indicators if i["verification_status"] in ("Suspicious", "Reported Unverified")]

    return {
        "engine_status": "Operational",
        "worker_running": cti_collector_worker._running,
        "interval_minutes": int(cti_collector_worker.interval_seconds / 60),
        "total_sources": len(sources),
        "total_indicators": len(indicators),
        "verified_malicious_count": len(verified),
        "suspicious_count": len(suspicious),
    }


@router.post("/collect")
async def trigger_cti_collection(
    user_id: str = Depends(current_user_id),
    role: str = Depends(require_role(["super_admin", "fraud_analyst"])),
):
    """Administrator / Analyst endpoint to manually trigger a CTI intelligence collection round."""
    try:
        results = await cti_collector_worker.run_now()
        failed = sum(row.get("status") in {"Failed", "Unconfigured"} for row in results)
        return {"status": "Completed with failures" if failed else "Collection Completed",
                "sources_processed": len(results), "failed_sources": failed, "details": results}
    except Exception as err:
        raise HTTPException(status_code=500, detail=f"Manual collection trigger failed: {err}")


@router.get("/sources")
def get_cti_sources(user_id: str = Depends(current_user_id)):
    """Lists registered CTI sources, synchronization checkpoints, and health statistics."""
    return cti_db.get_sources()


@router.get("/indicators")
def get_cti_indicators(
    indicator_type: Optional[str] = Query(default=None, description="Filter by type: url, domain, ip, hash, email, vpa"),
    verification_status: Optional[str] = Query(default=None, description="Filter by status: Verified Malicious, Reported Unverified, Suspicious, Allowlisted, Expired"),
    source_name: Optional[str] = Query(default=None, description="Filter by source name"),
    search: Optional[str] = Query(default=None, description="Search indicator value or description"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    user_id: str = Depends(current_user_id),
):
    """Paginated retrieval of extracted CTI threat indicators with filtering."""
    all_results = cti_db.query_indicators(
        indicator_type=indicator_type,
        verification_status=verification_status,
        source_name=source_name,
        search_query=search,
        limit=5000,
    )
    paginated = all_results[offset : offset + limit]
    return {
        "total": len(all_results),
        "limit": limit,
        "offset": offset,
        "indicators": paginated,
    }


@router.get("/indicators/{indicator_id}")
def get_cti_indicator_details(indicator_id: str, user_id: str = Depends(current_user_id)):
    """Retrieves single indicator details, evidence payload, and review history."""
    results = cti_db.query_indicators(limit=5000)
    match = next((i for i in results if i["indicator_id"] == indicator_id), None)
    if not match:
        raise HTTPException(status_code=404, detail="Indicator not found")
    return match


@router.get("/fraud-patterns")
def get_cti_fraud_patterns(user_id: str = Depends(current_user_id)):
    """Lists extracted scam patterns, keywords, and attack vectors."""
    from cti_extraction import SCAM_CATEGORIES
    patterns = []
    for cat, kws in SCAM_CATEGORIES.items():
        patterns.append({
            "category": cat,
            "pattern_name": cat.replace("_", " ").title(),
            "keywords": kws,
            "description": f"Scam pattern category for {cat.replace('_', ' ')}.",
        })
    return patterns


@router.get("/collection-logs")
def get_cti_collection_logs(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    user_id: str = Depends(current_user_id),
):
    """Paginated retrieval of historical CTI background collection logs."""
    all_logs = cti_db.get_collection_logs(limit=1000)
    paginated = all_logs[offset : offset + limit]
    return {
        "total": len(all_logs),
        "limit": limit,
        "offset": offset,
        "logs": paginated,
    }


@router.post("/indicators/{indicator_id}/review")
def review_cti_indicator(
    indicator_id: str,
    req: IndicatorReviewRequest,
    reviewer_id: str = Depends(current_user_id),
    role: str = Depends(require_role(["super_admin", "fraud_analyst"])),
):
    """Analyst endpoint for reviewing and updating indicator verification status."""
    valid_statuses = {"Verified Malicious", "Reported Unverified", "Suspicious", "Allowlisted", "Expired"}
    if req.new_status not in valid_statuses:
        raise HTTPException(status_code=422, detail=f"Invalid verification status. Must be one of {valid_statuses}")

    success = cti_db.review_indicator(
        indicator_id=indicator_id,
        reviewer_id=reviewer_id,
        new_status=req.new_status,
        notes=req.review_notes,
    )
    if not success:
        raise HTTPException(status_code=404, detail="Indicator not found")
    cti_matcher.invalidate_cache(indicator_id)
    return {"status": "Updated", "indicator_id": indicator_id, "new_status": req.new_status}

@router.get("/indicators/{indicator_id}/reviews")
def get_indicator_review_history(indicator_id: str, user_id: str = Depends(current_user_id)):
    rows = cti_db.get_indicator_reviews(indicator_id)
    if rows is None:
        raise HTTPException(status_code=404, detail="Indicator not found")
    return {"indicator_id": indicator_id, "reviews": rows}

@router.get("/quarantine-candidates")
def get_quarantine_candidates(user_id: str = Depends(current_user_id),
                              role: str = Depends(require_role(["super_admin"]))):
    return {"candidates": cti_db.get_quarantine_candidates()}

class QuarantineRequest(BaseModel):
    reason: str = Field(..., min_length=4, max_length=1000)

@router.post("/indicators/{indicator_id}/quarantine")
def quarantine_indicator(indicator_id: str, req: QuarantineRequest,
                         actor: str = Depends(current_user_id),
                         role: str = Depends(require_role(["super_admin"]))):
    if not cti_db.quarantine_indicator(indicator_id, req.reason, actor):
        raise HTTPException(status_code=404, detail="Indicator not found")
    cti_matcher.invalidate_cache(indicator_id)
    return {"status": "Quarantined", "indicator_id": indicator_id}


# --- MODEL REGISTRY & CONTINUOUS ML PIPELINE ENDPOINTS ---

@router.get("/models")
def get_cti_models(user_id: str = Depends(current_user_id)):
    """Lists registered ML models, active version, metrics, and approval statuses."""
    from cti_ml_pipeline import cti_registry
    return cti_registry.list_models()


@router.get("/models/evaluations")
def get_model_evaluations(user_id: str = Depends(current_user_id)):
    """Retrieves evaluation comparison metrics for candidate and production models."""
    from cti_ml_pipeline import cti_registry
    models = cti_registry.list_models()
    return {"total_models": len(models), "evaluations": models}


@router.get("/models/monitoring")
def get_model_monitoring(user_id: str = Depends(current_user_id)):
    """Retrieves statistical data drift & model latency monitoring reports."""
    from model_monitor import model_monitor
    return model_monitor.get_performance_summary()


@router.get("/models/{model_id}")
def get_model_details(model_id: str, user_id: str = Depends(current_user_id)):
    """Retrieves single model metadata, metrics, and deployment history."""
    from cti_ml_pipeline import cti_registry
    model = cti_registry.get_model(model_id)
    if not model:
        raise HTTPException(status_code=404, detail="Model ID not found")
    return model


@router.post("/models/train")
def train_candidate_model(
    req: ModelTrainRequest,
    user_id: str = Depends(current_user_id),
    role: str = Depends(require_role(["super_admin", "fraud_analyst"])),
):
    """Triggers candidate ML model training on validated quality-controlled datasets."""
    from cti_ml_pipeline import cti_evaluator
    try:
        res = cti_evaluator.train_and_evaluate(algorithm=req.algorithm, dataset_version=req.dataset_version)
        return {"status": "Candidate Model Trained", "candidate": res}
    except Exception as err:
        raise HTTPException(status_code=422, detail=f"Training failed: {err}")


@router.post("/models/{model_id}/approve")
def approve_model(
    model_id: str,
    user_id: str = Depends(current_user_id),
    role: str = Depends(require_role(["super_admin"])),
):
    """Administrator endpoint to approve a candidate model after performance review."""
    from cti_ml_pipeline import cti_registry
    success = cti_registry.approve_model(model_id, actor=user_id)
    if not success:
        raise HTTPException(status_code=422, detail="Model approval failed or model not in Pending Approval status")
    return {"status": "Approved", "model_id": model_id}


@router.post("/models/{model_id}/deploy")
def deploy_model(
    model_id: str,
    user_id: str = Depends(current_user_id),
    role: str = Depends(require_role(["super_admin"])),
):
    """Administrator endpoint to deploy an approved candidate model to active production."""
    from cti_ml_pipeline import cti_registry
    success = cti_registry.deploy_model(model_id, actor=user_id)
    if not success:
        raise HTTPException(status_code=422, detail="Model deployment rejected: candidate must be approved, checksum/schema compatible, and have eligible temporal evaluation.")
    return {"status": "Deployed", "model_id": model_id}


@router.post("/models/{model_id}/rollback")
def rollback_model(
    model_id: str,
    user_id: str = Depends(current_user_id),
    role: str = Depends(require_role(["super_admin"])),
):
    """Administrator endpoint to rollback a deployed model to a previous active version."""
    from cti_ml_pipeline import cti_registry
    success = cti_registry.rollback_model(model_id, actor=user_id)
    if not success:
        raise HTTPException(status_code=422, detail="Model rollback failed")
    return {"status": "Rolled Back", "model_id": model_id}
