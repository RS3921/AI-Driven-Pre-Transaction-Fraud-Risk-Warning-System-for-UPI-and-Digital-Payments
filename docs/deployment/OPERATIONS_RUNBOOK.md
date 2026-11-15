# Operations Runbook — UPI Fraud Guard Enterprise

This runbook documents operational procedures, database maintenance, model lifecycle management, incident response, and troubleshooting.

---

## 1. Service Lifecycle Management

### Starting the Backend
```bash
cd upi-fraud-guard-v3
source venv/bin/activate  # or .\venv\Scripts\Activate.ps1
python run_api.py
```

### Graceful Shutdown
Send `SIGINT` (Ctrl+C in terminal) or `SIGTERM`.  
FastAPI runs the `@app.on_event("shutdown")` lifecycle handler:
1. Cancels the background CTI collector task.
2. Waits for any executing connector thread to complete.
3. Releases the single-instance lock file (`data/cti_collector.lock`).
4. Flushes database connections cleanly.

---

## 2. Database Backup & Maintenance

The SQLite database is located at `data/risk_checks.db`.

### Online Backup Procedure (Zero Downtime)
SQLite supports atomic online backups via the sqlite3 CLI:
```bash
# Atomic online backup
sqlite3 data/risk_checks.db ".backup 'data/backups/risk_checks_$(date +%Y%m%d_%H%M%S).db'"
```

### Retention Policy
- `risk_checks`: Logs older than 30 days are automatically pruned by `enforce_retention()` on 5% of incoming transactions.
- `cti_indicators`: Expired indicators are naturally excluded from matching via `expires_at` checks.

### Emergency Database Recovery
If `risk_checks.db` becomes corrupted:
1. Stop the application.
2. Move corrupted file: `mv data/risk_checks.db data/risk_checks.db.corrupt`.
3. Restore from latest verified backup: `cp data/backups/risk_checks_latest.db data/risk_checks.db`.
4. Restart the service: `python run_api.py`. Schemas and indexes will be verified automatically.

---

## 3. Machine Learning Model Operations

### Candidate Model Training
To trigger training via REST API:
```bash
curl -X POST http://127.0.0.1:8000/api/intelligence/models/train \
  -H "Authorization: Bearer <ANALYST_OR_ADMIN_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"algorithm": "RandomForest", "dataset_version": "paysim-processed-v1"}'
```

### Model Approval
```bash
curl -X POST http://127.0.0.1:8000/api/intelligence/models/<MODEL_ID>/approve \
  -H "Authorization: Bearer <ADMIN_TOKEN>"
```

### Production Deployment Policy
- Deployment requires: (1) Approved status, (2) Checksum verification, and (3) Eligible temporal evaluation.
- If deployment is rejected due to lack of temporal evaluation, the candidate remains approved in the registry without overwriting the production inference engine.

### Emergency Rollback
If an active model exhibits anomalous behavior:
```bash
curl -X POST http://127.0.0.1:8000/api/intelligence/models/<ACTIVE_MODEL_ID>/rollback \
  -H "Authorization: Bearer <ADMIN_TOKEN>"
```
Rollback restores the previous active model artifact and verifies its SHA-256 checksum before updating `active_transaction_model.json`.

---

## 4. Threat Intelligence Operations

### Quarantining False Positives
If an indicator is reported as a false positive:
```bash
curl -X POST http://127.0.0.1:8000/api/intelligence/indicators/<INDICATOR_ID>/quarantine \
  -H "Authorization: Bearer <ADMIN_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"reason": "Legitimate merchant domain falsely flagged in external advisory"}'
```
*Effect:* `quarantined=1` is updated in SQLite, and the matcher cache is flushed immediately.

### Manual CTI Sync Trigger
```bash
curl -X POST http://127.0.0.1:8000/api/intelligence/collect \
  -H "Authorization: Bearer <ANALYST_OR_ADMIN_TOKEN>"
```

---

## 5. Troubleshooting & Common Incidents

| Symptom | Root Cause | Resolution |
| :--- | :--- | :--- |
| `Refusing network binding without API users` | `UPI_FRAUD_GUARD_HOST` is bound to external interface while auth is disabled. | Set `UPI_FRAUD_GUARD_REQUIRE_AUTH=true` and configure `UPI_FRAUD_GUARD_API_USERS`. |
| `Refusing network binding without HTTPS` | Binding to external interface without TLS certificates. | Configure valid `UPI_FRAUD_GUARD_TLS_CERT` and `UPI_FRAUD_GUARD_TLS_KEY`. |
| `Another CTI background worker instance is already active` | Stale lock file after abrupt OS crash. | Lock file auto-cleans after 2 hours. To force reset, verify no Python process is running, then delete `data/cti_collector.lock`. |
| `CTI source ... failed: HTTP 403` | Upstream advisory website blocked scraper user-agent. | Normal resilient behavior. Connector logs `Failed` status without creating fake records. |
| `Refusing model deployment: candidate lacks eligible temporal evaluation` | Candidate trained on dataset without timestamps. | Intended security control. Candidate is kept in registry for review; production model is not modified. |
