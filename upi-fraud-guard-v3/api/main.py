"""FastAPI application for the multimodal UPI pre-transaction risk platform."""
from __future__ import annotations
import json, random, sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional
import joblib
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from risk_fusion import fuse
from multilingual_message_rules import analyse_multilingual_message, is_explicitly_safe_context
from transaction_module.analyzer import analyse_transaction
from url_qr_module.analyzer import analyse_url
from url_qr_module.qr_decoder import decode_qr_image
from api.security import (
    authentication_required,
    current_user_id,
    current_user_role,
    require_role,
    validate_security_configuration,
)
from dual_feed import dual_feed_engine
from mule_detection import mule_detector
from investigation import investigation_manager
from model_monitor import model_monitor
from cti_collector import cti_collector_worker
from cti_api import router as cti_router
from auie_api import router as auie_router
from cti_matcher import cti_matcher

BASE_DIR = Path(__file__).resolve().parent.parent
MODELS_DIR, FRONTEND_DIR, DB_PATH = BASE_DIR / "models", BASE_DIR / "frontend", BASE_DIR / "data" / "risk_checks.db"
app = FastAPI(
    title="UPI Fraud Guard Enterprise API",
    description="Explainable pre-transaction risk, dual-feed threat intelligence, and mule account detection platform.",
    version="2.6.0-Enterprise",
    docs_url="/api-docs",
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"],
    allow_methods=["GET", "POST", "DELETE", "PUT"],
    allow_headers=["*"],
)
app.include_router(cti_router)
app.include_router(auie_router)

nlp_model = joblib.load(MODELS_DIR / "nlp_model.joblib")
nlp_vectorizer = joblib.load(MODELS_DIR / "nlp_vectorizer.joblib")


class RiskCheckRequest(BaseModel):
    message: str = Field(default="", max_length=2000)
    url_or_qr: str = Field(default="", max_length=2000)
    amount: float | None = Field(default=None, ge=0, le=10_000_000)
    recipient: str = Field(default="", max_length=150)
    payments_last_hour: int | None = Field(default=None, ge=0, le=100)
    is_new_recipient: bool | None = None


class CaseUpdateRequest(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    add_note: Optional[str] = None


class ThreatVpaRequest(BaseModel):
    vpa: str = Field(..., max_length=150)


AUDIT_LOG_RETENTION_DAYS = 30
MAX_QR_IMAGE_BYTES = 5 * 1024 * 1024


def initialise_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS risk_checks (id INTEGER PRIMARY KEY, created_at TEXT, verdict TEXT, risk_score REAL, modules_used TEXT, reasons TEXT, message TEXT, url_or_qr TEXT, amount REAL, recipient TEXT, user_id TEXT NOT NULL DEFAULT 'local-development')"
        )
        columns = {row[1] for row in conn.execute("PRAGMA table_info(risk_checks)")}
        if "user_id" not in columns:
            conn.execute("ALTER TABLE risk_checks ADD COLUMN user_id TEXT NOT NULL DEFAULT 'local-development'")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_risk_checks_user_created ON risk_checks(user_id, created_at)")
        conn.commit()
    enforce_retention()


def enforce_retention():
    cutoff = (datetime.now(timezone.utc) - timedelta(days=AUDIT_LOG_RETENTION_DAYS)).isoformat()
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute("DELETE FROM risk_checks WHERE created_at < ?", (cutoff,))
        conn.commit()


def score_message(text: str) -> dict:
    if not text.strip():
        return {"score": None, "reasons": [], "shap_explanation": []}
    vector = nlp_vectorizer.transform([text])
    model_score = float(nlp_model.predict_proba(vector)[0][1])
    explicit_safe_context = is_explicitly_safe_context(text)
    if explicit_safe_context:
        model_score = min(model_score, 0.22)
    rule_score, rule_reasons = analyse_multilingual_message(text)
    score = max(model_score, rule_score or 0.0)
    reasons = list(rule_reasons)

    # Correlate with active verified CTI threat indicators / patterns
    cti_msg_match = cti_matcher.match_message_patterns(text)
    if cti_msg_match:
        score = max(score, 0.88)
        reasons.insert(0, f"CRITICAL: Message contains verified threat indicator '{cti_msg_match['matched_value']}' ({cti_msg_match['source_name']})")

    if not reasons and explicit_safe_context:
        reasons.append("This is a safety reminder or routine notice with no active scam request")
    if not reasons and model_score >= 0.3:
        reasons.append("Message matches patterns seen in the English scam/spam training examples")
    if not reasons:
        reasons.append("No strong supported-language scam cues were found; this does not prove the message is safe")

    feature_names = nlp_vectorizer.get_feature_names_out()
    nonzero_idx = vector.nonzero()[1]
    contributions = [(feature_names[i], float(nlp_model.coef_[0][i] * vector[0, i])) for i in nonzero_idx]
    contributions.sort(key=lambda p: abs(p[1]), reverse=True)
    shap_explanation = [
        {"feature": word, "label": f'Word "{word}"', "contribution": round(c, 4), "direction": "increased_risk" if c > 0 else "decreased_risk"}
        for word, c in contributions[:4] if abs(c) > 1e-4
    ]
    out_res = {"score": round(score, 3), "reasons": reasons, "shap_explanation": shap_explanation}
    if cti_msg_match:
        out_res["cti_match"] = cti_msg_match
    return out_res


def persist(payload, result, user_id: str) -> int:
    with closing(sqlite3.connect(DB_PATH)) as conn:
        cursor = conn.execute(
            "INSERT INTO risk_checks (created_at, verdict, risk_score, modules_used, reasons, message, url_or_qr, amount, recipient, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                datetime.now(timezone.utc).isoformat(),
                result["verdict"],
                result["risk_score"],
                json.dumps(result["modules_used"]),
                json.dumps(result["reasons"]),
                payload.message[:1000],
                payload.url_or_qr[:1000],
                payload.amount,
                payload.recipient[:150],
                user_id,
            ),
        )
        conn.commit()
        check_id = cursor.lastrowid
    if random.random() < 0.05:
        enforce_retention()
    return check_id


@app.on_event("startup")
async def startup():
    validate_security_configuration()
    initialise_db()
    await cti_collector_worker.start()


@app.on_event("shutdown")
async def shutdown():
    await cti_collector_worker.shutdown()


@app.get("/status")
def status():
    return {
        "status": "running",
        "version": "2.6.0-Enterprise",
        "authentication_required": authentication_required(),
        "modules": ["message", "url_qr", "transaction", "dual_feed", "mule_detection", "investigations"],
        "features": [
            "Dual-Feed Threat Intelligence correlation",
            "NetworkX Graph-Based Mule Account Detection",
            "Fraud Investigation Centre & Case Lifecycle Management",
            "Role-Based Access Control (RBAC)",
            "Model Performance Drift Monitoring",
        ],
    }


@app.get("/session")
def session(user_id: str = Depends(current_user_id), role: str = Depends(current_user_role)):
    return {"user_id": user_id, "role": role, "authenticated": user_id != "local-development"}


@app.post("/check")
def check(payload: RiskCheckRequest, user_id: str = Depends(current_user_id)):
    if not any((payload.message.strip(), payload.url_or_qr.strip(), payload.amount is not None,
                payload.recipient.strip(), payload.payments_last_hour is not None,
                payload.is_new_recipient is not None)):
        raise HTTPException(status_code=422, detail="Add a message, link/QR, or transaction detail before checking.")

    message = score_message(payload.message)
    url = analyse_url(payload.url_or_qr)
    transaction = analyse_transaction(payload.amount, payload.recipient, payload.payments_last_hour, payload.is_new_recipient)

    # Dual-feed correlation
    dual_feed_corr = dual_feed_engine.correlate_check(
        vpa=payload.recipient,
        url_or_qr=payload.url_or_qr,
        amount=payload.amount,
        payments_last_hour=payload.payments_last_hour,
        is_new_recipient=payload.is_new_recipient,
    )

    result = fuse(message, url, transaction)

    # Merge dual-feed intelligence
    if dual_feed_corr["matched_indicators"]:
        result["reasons"].extend(dual_feed_corr["matched_indicators"])
        if dual_feed_corr["threat_match_score"] > 0:
            result["risk_score"] = round(max(result["risk_score"], dual_feed_corr["combined_score"]), 3)
            result["risk_score_100"] = int(round(result["risk_score"] * 100))
            if result["risk_score"] >= 0.85:
                result["verdict"] = "High Risk"
                result["risk_tier"] = "Critical"
                result["recommended_action"] = "CRITICAL ALERT: Recommend stopping transaction until independently verified."
            elif result["risk_score"] >= 0.65:
                result["verdict"] = "High Risk"
                result["risk_tier"] = "High"
                result["recommended_action"] = "HIGH RISK: Warn user and recommend verifying payee identity directly before approving payment."
            elif result["risk_score"] >= 0.30:
                result["verdict"] = "Suspicious"
                result["risk_tier"] = "Medium"
                result["recommended_action"] = "MEDIUM RISK: Request additional payee verification before confirming payment."

    if url.get("upi_qr_details") is not None:
        result["upi_qr_details"] = url["upi_qr_details"]

    result["module_scores"] = {
        "message": message["score"],
        "url_qr": url["score"],
        "transaction": transaction["score"],
        "dual_feed": dual_feed_corr["combined_score"],
    }

    result["shap_explanations"] = {
        "message": message.get("shap_explanation", []),
        "url_qr": url.get("shap_explanation", []),
        "transaction": transaction.get("shap_explanation", []),
    }

    # Register in graph mule detector if recipient present
    if payload.recipient:
        mule_detector.add_transaction(sender=user_id, receiver=payload.recipient, amount=payload.amount or 0.0)

    check_id = persist(payload, result, user_id)

    # Register in investigation queue if flagged
    if result["verdict"] in ("Suspicious", "High Risk"):
        case_id = investigation_manager.create_case_from_check(
            check_id=check_id,
            verdict=result["verdict"],
            risk_score=result["risk_score"],
            message=payload.message,
            url_or_qr=payload.url_or_qr,
            amount=payload.amount,
            recipient=payload.recipient,
            reasons=result["reasons"],
        )
        result["investigation_case_id"] = case_id

    return result


@app.get("/feed-status")
def feed_status(user_id: str = Depends(current_user_id)):
    return {
        "threat_feed": dual_feed_engine.threat_feed.get_status(),
        "transaction_feed": dual_feed_engine.txn_feed.get_status(),
    }


@app.post("/threat-intelligence/add-vpa")
def add_threat_vpa(req: ThreatVpaRequest, role: str = Depends(require_role(["super_admin", "fraud_analyst"]))):
    dual_feed_engine.threat_feed.add_threat_vpa(req.vpa)
    return {"status": "VPA added to Threat Intelligence feed", "vpa": req.vpa}


@app.get("/mule-analysis")
def mule_analysis(user_id: str = Depends(current_user_id)):
    return mule_detector.get_network_summary()


@app.get("/mule-analysis/{vpa}")
def mule_analysis_account(vpa: str, user_id: str = Depends(current_user_id)):
    return mule_detector.analyze_account(vpa)


@app.get("/investigations")
def list_investigations(
    status: Optional[str] = None,
    priority: Optional[str] = None,
    limit: int = 50,
    user_id: str = Depends(current_user_id),
):
    return investigation_manager.list_cases(status=status, priority=priority, limit=limit)


@app.get("/investigations/{case_id}")
def get_investigation(case_id: str, user_id: str = Depends(current_user_id)):
    case = investigation_manager.get_case_details(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Investigation case not found")
    return case


@app.post("/investigations/{case_id}/update")
def update_investigation(
    case_id: str,
    req: CaseUpdateRequest,
    actor: str = Depends(current_user_id),
):
    success = investigation_manager.update_case(
        case_id=case_id,
        actor=actor,
        new_status=req.status,
        assigned_to=req.assigned_to,
        add_note=req.add_note,
    )
    if not success:
        raise HTTPException(status_code=404, detail="Case not found or update failed")
    return {"status": "Updated", "case_id": case_id}


@app.get("/model-monitoring")
def get_model_monitoring(user_id: str = Depends(current_user_id)):
    # Retrieve recent scores from DB for drift evaluation
    with closing(sqlite3.connect(DB_PATH)) as conn:
        rows = conn.execute("SELECT risk_score FROM risk_checks ORDER BY id DESC LIMIT 100").fetchall()
    recent_scores = [r[0] for r in rows]
    drift_analysis = model_monitor.check_data_drift(recent_scores)
    return {
        "drift_analysis": drift_analysis,
        "performance": model_monitor.get_performance_summary(),
    }


@app.post("/scan-qr")
async def scan_qr(image: UploadFile = File(...), user_id: str = Depends(current_user_id)):
    if image.content_type and not image.content_type.startswith("image/"):
        raise HTTPException(status_code=415, detail="Please upload an image file.")
    try:
        image_bytes = await image.read(MAX_QR_IMAGE_BYTES + 1)
        if len(image_bytes) > MAX_QR_IMAGE_BYTES:
            raise HTTPException(status_code=413, detail="QR image must be 5 MB or smaller.")
        payload = decode_qr_image(image_bytes)
        analysis = analyse_url(payload)
        return {
            "payload": payload,
            "kind": analysis["kind"],
            "risk_score": analysis["score"],
            "reasons": analysis["reasons"],
            "upi_qr_details": analysis.get("upi_qr_details"),
        }
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


@app.get("/history")
def history(limit: int = 10, start: str | None = None, end: str | None = None, user_id: str = Depends(current_user_id)):
    enforce_retention()
    query = "SELECT created_at, verdict, risk_score, modules_used, reasons, message, url_or_qr, amount, recipient FROM risk_checks WHERE user_id = ?"
    params: list = [user_id]
    if start:
        query += " AND created_at >= ?"
        params.append(start)
        if end:
            query += " AND created_at <= ?"
            params.append(end)
    elif end:
        query += " AND created_at <= ?"
        params.append(end)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(max(1, min(limit, 5000)))
    with closing(sqlite3.connect(DB_PATH)) as conn:
        rows = conn.execute(query, params).fetchall()
    keys = ["created_at", "verdict", "risk_score", "modules_used", "reasons", "message", "url_or_qr", "amount", "recipient"]
    items = []
    for row in rows:
        item = {**dict(zip(keys, row)), "modules_used": json.loads(row[3]), "reasons": json.loads(row[4])}
        if item["url_or_qr"].strip().lower().startswith("upi://"):
            item["upi_qr_details"] = analyse_url(item["url_or_qr"]).get("upi_qr_details")
        items.append(item)
    return items


@app.delete("/history")
def delete_history(user_id: str = Depends(current_user_id)):
    with closing(sqlite3.connect(DB_PATH)) as conn:
        cursor = conn.execute("DELETE FROM risk_checks WHERE user_id = ?", (user_id,))
        conn.commit()
        return {"deleted_count": cursor.rowcount}


@app.get("/analytics")
def analytics(days: int = 7, start: str | None = None, end: str | None = None, user_id: str = Depends(current_user_id)):
    now = datetime.now(timezone.utc)
    if start and end:
        try:
            range_start = datetime.fromisoformat(start.replace("Z", "+00:00"))
            range_end = datetime.fromisoformat(end.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(status_code=422, detail="start/end must be ISO 8601 datetimes.")
        if range_start > range_end:
            range_start, range_end = range_end, range_start
    else:
        days = max(1, min(days, 365))
        range_start = now - timedelta(days=days)
        range_end = now

    span_hours = max((range_end - range_start).total_seconds() / 3600, 0.01)
    bucket_by_hour = span_hours <= 48
    bucket_len = 13 if bucket_by_hour else 10

    with closing(sqlite3.connect(DB_PATH)) as conn:
        rows = conn.execute(
            "SELECT created_at, verdict, risk_score FROM risk_checks WHERE user_id = ? AND created_at >= ? AND created_at <= ? ORDER BY created_at",
            (user_id, range_start.isoformat(), range_end.isoformat()),
        ).fetchall()

    counts = {"Safe": 0, "Suspicious": 0, "High Risk": 0}
    buckets: dict[str, dict] = {}
    for created_at, verdict, score in rows:
        counts[verdict] = counts.get(verdict, 0) + 1
        b = buckets.setdefault(created_at[:bucket_len], {"scores": [], "flagged": 0, "clear": 0})
        b["scores"].append(score)
        if verdict == "Safe":
            b["clear"] += 1
        else:
            b["flagged"] += 1

    series = [
        {"label": key, "avg_risk": round(sum(v["scores"]) / len(v["scores"]), 3), "checks": len(v["scores"]), "flagged": v["flagged"], "clear": v["clear"]}
        for key, v in sorted(buckets.items())
    ]
    total = len(rows)
    return {
        "range_start": range_start.isoformat(),
        "range_end": range_end.isoformat(),
        "bucket": "hour" if bucket_by_hour else "day",
        "total": total,
        "counts": counts,
        "avg_risk": round(sum(row[2] for row in rows) / total, 3) if total else 0,
        "series": series,
        "high_risk_rate": round((counts["High Risk"] / total) * 100, 1) if total else 0,
    }


@app.get("/model-metrics")
def model_metrics(user_id: str = Depends(current_user_id)):
    names = {
        "nlp": "nlp_metrics.json",
        "multilingual_smoke": "multilingual_eval_metrics.json",
        "multilingual_external": "multilingual_external_metrics.json",
        "native_language_reviewed": "native_language_reviewed_metrics.json",
        "url": "url_metrics.json",
        "transaction": "transaction_metrics.json",
    }
    out = {}
    for key, filename in names.items():
        path = MODELS_DIR / filename
        out[key] = json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
    if not any(out.values()):
        raise HTTPException(status_code=404, detail="Train the models with python setup.py to generate metrics.")
    return out


app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
