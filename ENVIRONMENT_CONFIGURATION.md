# Environment Configuration Guide — UPI Fraud Guard

This document details all supported configuration variables, their types, security requirements, and defaults.

---

## 1. Network & Server Configuration

| Variable | Type | Default | Staging / Prod Requirement | Description |
| :--- | :---: | :---: | :---: | :--- |
| `UPI_FRAUD_GUARD_HOST` | String | `127.0.0.1` | Set to host IP or `0.0.0.0` | Binding network interface address. |
| `UPI_FRAUD_GUARD_PORT` | Integer | `8000` | Typically `8000` or `443` | Listening TCP port. |
| `UPI_FRAUD_GUARD_TLS_CERT` | File Path | `""` | **Mandatory** if non-loopback | Path to PEM-encoded TLS certificate file. |
| `UPI_FRAUD_GUARD_TLS_KEY` | File Path | `""` | **Mandatory** if non-loopback | Path to PEM-encoded private key file. |

*Security Rule:* If `UPI_FRAUD_GUARD_HOST` is bound to any non-loopback address (not `127.0.0.1` or `localhost`), `run_api.py` refuses to start without both `UPI_FRAUD_GUARD_TLS_CERT` and `UPI_FRAUD_GUARD_TLS_KEY` configured.

---

## 2. Authentication & Authorization (RBAC)

| Variable | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `UPI_FRAUD_GUARD_REQUIRE_AUTH` | Boolean | `false` | When `true`, all non-public endpoints require a valid Bearer token. |
| `UPI_FRAUD_GUARD_API_USERS` | JSON String | `"{}"` | Mapping of usernames to 32+ character Bearer tokens. |

### Generating Secure Tokens
Tokens must be high-entropy random strings of at least 32 characters:
```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

### Supported User Role Mappings
In `api/security.py`, predefined usernames inherit specific roles:
- `admin` ➔ `super_admin` (Full permissions: model deploy, rollback, approve, quarantine)
- `analyst` ➔ `fraud_analyst` (Risk checks, CTI trigger, indicator review, model training)
- `investigator` ➔ `investigation_officer` (Case management, notes, status updates)
- `auditor` ➔ `read_only_auditor` (Read-only analytics and monitoring logs)

Example valid JSON:
```json
{
  "admin": "d4e7f8a9b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9",
  "analyst": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
}
```

---

## 3. Cyber Threat Intelligence (CTI) Sources

| Variable | Type | Required | Description |
| :--- | :---: | :---: | :--- |
| `ABUSEIPDB_API_KEY` | String | Optional | API key for AbuseIPDB IP reputation queries. |
| `OTX_API_KEY` | String | Optional | AlienVault Open Threat Exchange (OTX) API key. |
| `CTI_COLLECTION_INTERVAL_MINUTES` | Float | `30` | Interval in minutes between autonomous background collection cycles. |

*Behavior when keys are missing:* The adapter reports status `Unconfigured` in `/api/intelligence/sources` without throwing exceptions or generating fake indicators.

---

## 4. Machine Learning & Model Registry

| Variable | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `UPI_FRAUD_GUARD_REBUILD_TRANSACTIONS` | Integer | `0` | Set to `1` during setup to force regeneration of `transactions_dataset.csv` from raw PaySim data. |

- Active model pointer path: `models/active_transaction_model.json`
- Candidate model storage: `models/candidates/MODEL-TRANSACTION-{version}.joblib`
