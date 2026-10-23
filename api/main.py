"""FastAPI application for the multimodal UPI pre-transaction risk demo."""
from __future__ import annotations
import json, random, sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
import joblib
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from risk_fusion import fuse
from multilingual_message_rules import analyse_multilingual_message, is_explicitly_safe_context
from transaction_module.analyzer import analyse_transaction
from url_qr_module.analyzer import analyse_url
from url_qr_module.qr_decoder import decode_qr_image
from api.security import authentication_required, current_user_id, validate_security_configuration

BASE_DIR = Path(__file__).resolve().parent.parent
MODELS_DIR, FRONTEND_DIR, DB_PATH = BASE_DIR / "models", BASE_DIR / "frontend", BASE_DIR / "data" / "risk_checks.db"
app = FastAPI(title="UPI Fraud Guard API", description="Explainable pre-transaction risk checks.", version="2.6.0", docs_url="/api-docs", redoc_url=None)
# Restricted to localhost -- this is a local-first prototype, never meant
# to be exposed to arbitrary origins. Update this list if you deploy it
# behind a real domain.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"],
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)
nlp_model, nlp_vectorizer = joblib.load(MODELS_DIR / "nlp_model.joblib"), joblib.load(MODELS_DIR / "nlp_vectorizer.joblib")

class RiskCheckRequest(BaseModel):
    # max_length limits below are a basic input-hardening measure -- stop
    # oversized payloads before they reach the model/DB layer at all.
    message: str = Field(default="", max_length=2000)
    url_or_qr: str = Field(default="", max_length=2000)
    amount: float | None = Field(default=None, ge=0, le=10_000_000)
    recipient: str = Field(default="", max_length=150)
    payments_last_hour: int | None = Field(default=None, ge=0, le=100)
    is_new_recipient: bool | None = None

def initialise_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS risk_checks (id INTEGER PRIMARY KEY, created_at TEXT, verdict TEXT, risk_score REAL, modules_used TEXT, reasons TEXT, message TEXT, url_or_qr TEXT, amount REAL, recipient TEXT, user_id TEXT NOT NULL DEFAULT 'local-development')")
        columns = {row[1] for row in conn.execute("PRAGMA table_info(risk_checks)")}
        if "user_id" not in columns:
            conn.execute("ALTER TABLE risk_checks ADD COLUMN user_id TEXT NOT NULL DEFAULT 'local-development'")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_risk_checks_user_created ON risk_checks(user_id, created_at)")
        conn.commit()
    enforce_retention()

# How long completed checks stay in the local audit log before being
# automatically purged -- a basic privacy/security-hygiene measure so
# the SQLite file doesn't grow forever and doesn't hold message/URL/
# recipient text longer than genuinely useful for a local demo. Kept as
# a simple constant here rather than a config file, since this is a
# local-first prototype, not a multi-tenant service.
AUDIT_LOG_RETENTION_DAYS = 30
MAX_QR_IMAGE_BYTES = 5 * 1024 * 1024

def enforce_retention():
    """Deletes audit records older than AUDIT_LOG_RETENTION_DAYS. Runs on
    every server startup, and after every new check is written, so the
    log never silently grows unbounded."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=AUDIT_LOG_RETENTION_DAYS)).isoformat()
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute("DELETE FROM risk_checks WHERE created_at < ?", (cutoff,))
        conn.commit()

def score_message(text: str) -> dict:
    if not text.strip(): return {"score": None, "reasons": [], "shap_explanation": []}
    vector = nlp_vectorizer.transform([text])
    model_score = float(nlp_model.predict_proba(vector)[0][1])
    explicit_safe_context = is_explicitly_safe_context(text)
    # The legacy SMS corpus often labels safety reminders and ordinary bank
    # notices as spam because they contain words like "account" or "OTP".
    # Cap that model-only suspicion when the text is clearly advisory or a
    # routine completed notice and contains no active scam cues.
    if explicit_safe_context:
        model_score = min(model_score, 0.22)
    rule_score, rule_reasons = analyse_multilingual_message(text)
    score = max(model_score, rule_score or 0.0)
    reasons = list(rule_reasons)
    if not reasons and explicit_safe_context:
        reasons.append("This is a safety reminder or routine notice with no active scam request")
    if not reasons and model_score >= .3:
        reasons.append("Message matches patterns seen in the English scam/spam training examples")
    if not reasons:
        reasons.append("No strong supported-language scam cues were found; this does not prove the message is safe")
    # Real per-prediction attribution for the linear model: for a logistic
    # regression over TF-IDF, each word's contribution to THIS prediction
    # is exactly (that word's model coefficient) x (its TF-IDF weight in
    # this message) -- the same underlying math SHAP's LinearExplainer
    # uses for linear models, computed directly since it's this simple
    # for a bag-of-words model.
    feature_names = nlp_vectorizer.get_feature_names_out()
    nonzero_idx = vector.nonzero()[1]
    contributions = [(feature_names[i], float(nlp_model.coef_[0][i] * vector[0, i])) for i in nonzero_idx]
    contributions.sort(key=lambda p: abs(p[1]), reverse=True)
    shap_explanation = [
        {"feature": word, "label": f'Word "{word}"', "contribution": round(c, 4), "direction": "increased_risk" if c > 0 else "decreased_risk"}
        for word, c in contributions[:4] if abs(c) > 1e-4
    ]
    return {"score": round(score, 3), "reasons": reasons, "shap_explanation": shap_explanation}

def persist(payload, result, user_id: str):
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute("INSERT INTO risk_checks (created_at, verdict, risk_score, modules_used, reasons, message, url_or_qr, amount, recipient, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (datetime.now(timezone.utc).isoformat(), result["verdict"], result["risk_score"], json.dumps(result["modules_used"]), json.dumps(result["reasons"]), payload.message[:1000], payload.url_or_qr[:1000], payload.amount, payload.recipient[:150], user_id))
        conn.commit()
    # Lightweight, non-blocking-ish retention sweep -- runs on a small
    # random fraction of writes rather than every single one, so the
    # log still gets pruned regularly without adding a DELETE query to
    # every request's hot path.
    if random.random() < 0.05:
        enforce_retention()

@app.on_event("startup")
def startup():
    validate_security_configuration()
    initialise_db()

@app.get("/status")
def status(): return {"status": "running", "version": "2.6.0", "authentication_required": authentication_required(), "modules": ["message", "url_qr", "transaction", "fusion"], "features": ["per-user API tokens and history isolation when configured", "per-user history deletion", "audit analytics", "model attribution", "time ranges", "shared word and character message classifier with equally weighted English, Hindi, Marathi, and Hinglish language buckets", "machine-translated Marathi training supplement and source-grouped diagnostic holdout", "native-speaker-reviewed language evaluation workflow", "parsed UPI QR payee, amount, currency, and anomaly fields (does not verify payee identity)", "pause/resume and source controls for notification monitoring in the Android app", "external multilingual held-out evaluation", "60-example balanced multilingual regression smoke set", f"{AUDIT_LOG_RETENTION_DAYS}-day audit log retention"]}

@app.get("/session")
def session(user_id: str = Depends(current_user_id)):
    # Authentication is determined by the request/configuration, not by a
    # reserved-looking user ID that an administrator could legitimately set.
    return {"user_id": user_id, "authenticated": authentication_required()}

@app.post("/check")
def check(payload: RiskCheckRequest, user_id: str = Depends(current_user_id)):
    if not any((payload.message.strip(), payload.url_or_qr.strip(), payload.amount is not None,
                payload.recipient.strip(), payload.payments_last_hour is not None,
                payload.is_new_recipient is not None)):
        raise HTTPException(status_code=422, detail="Add a message, link/QR, or transaction detail before checking.")
    message, url = score_message(payload.message), analyse_url(payload.url_or_qr)
    transaction = analyse_transaction(payload.amount, payload.recipient, payload.payments_last_hour, payload.is_new_recipient)
    result = fuse(message, url, transaction)
    if url.get("upi_qr_details") is not None:
        result["upi_qr_details"] = url["upi_qr_details"]
    result["module_scores"] = {"message": message["score"], "url_qr": url["score"], "transaction": transaction["score"]}
    # Real, per-prediction SHAP-based attribution (see shap_explainability.py)
    # for each module that actually ran on this request -- genuine model
    # attribution, not the rule-based "reasons" above.
    result["shap_explanations"] = {
        "message": message.get("shap_explanation", []),
        "url_qr": url.get("shap_explanation", []),
        "transaction": transaction.get("shap_explanation", []),
    }
    persist(payload, result, user_id)
    return result

@app.post("/check-message")
def check_message(payload: RiskCheckRequest, user_id: str = Depends(current_user_id)): return check(payload, user_id)

@app.post("/scan-qr")
async def scan_qr(image: UploadFile = File(...), user_id: str = Depends(current_user_id)):
    """Decode a QR image locally and score its payload without saving the image."""
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
        query += " AND created_at >= ?"; params.append(start)
        if end:
            query += " AND created_at <= ?"; params.append(end)
    elif end:
        query += " AND created_at <= ?"; params.append(end)
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
    """Delete all saved check history owned by the authenticated user."""
    with closing(sqlite3.connect(DB_PATH)) as conn:
        cursor = conn.execute("DELETE FROM risk_checks WHERE user_id = ?", (user_id,))
        conn.commit()
        return {"deleted_count": cursor.rowcount}

@app.get("/analytics")
def analytics(days: int = 7, start: str | None = None, end: str | None = None, user_id: str = Depends(current_user_id)):
    """Aggregate local audit data for the dashboard; no data leaves the device.

    Accepts EITHER a preset `days` window (24h/7d/30d buttons) OR an
    explicit `start`/`end` datetime range (the custom range picker) --
    if both start and end are given, they take priority over `days`.
    For a short window (<=2 days) the series is bucketed by HOUR instead
    of by day, so a custom range like "yesterday 2pm to today 6am" still
    shows meaningful granularity instead of collapsing into one point.
    """
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
    bucket_len = 13 if bucket_by_hour else 10  # "YYYY-MM-DDTHH" vs "YYYY-MM-DD"

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
        # "Flagged" groups Suspicious + High Risk (anything that should give a
        # user pause), mirroring the Flagged/Clear split used elsewhere in
        # our tooling, rather than a three-way split that's harder to trend.
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
    names = {"nlp": "nlp_metrics.json", "multilingual_smoke": "multilingual_eval_metrics.json", "multilingual_external": "multilingual_external_metrics.json", "native_language_reviewed": "native_language_reviewed_metrics.json", "url": "url_metrics.json", "transaction": "transaction_metrics.json"}
    out = {}
    for key, filename in names.items():
        path = MODELS_DIR / filename
        out[key] = json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
    if not any(out.values()):
        raise HTTPException(status_code=404, detail="Train the models with python setup.py to generate metrics.")
    return out

app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
