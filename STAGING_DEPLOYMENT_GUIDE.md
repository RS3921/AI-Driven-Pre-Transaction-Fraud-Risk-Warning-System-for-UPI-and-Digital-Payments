# Staging Deployment Guide — UPI Fraud Guard Enterprise v2.6.0-RC1

This guide provides instructions for deploying UPI Fraud Guard Enterprise into an isolated staging or pilot environment.

---

## 1. Prerequisites & System Requirements

- **Operating System:** Linux (Ubuntu 22.04 LTS recommended) or Windows Server
- **Python Runtime:** Python 3.10 to 3.13 (Python 3.13.14 verified)
- **Memory & Storage:** 4 GB RAM minimum (8 GB recommended for candidate model training); 5 GB free disk space
- **Network Access:** Outbound HTTPS access to allowlisted CTI feeds (CERT-In, PhishTank, URLhaus, OpenPhish, CISA, MITRE)

---

## 2. Step-by-Step Staging Setup

### Step 1: Clone and Enter Directory
```bash
git clone <repository_url> upi-fraud-guard
cd upi-fraud-guard/upi-fraud-guard-v3
```

### Step 2: Set Up Virtual Environment & Dependencies
```bash
python -m venv venv
# Linux / macOS
source venv/bin/activate
# Windows PowerShell
.\venv\Scripts\Activate.ps1

pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3: Configure Environment Variables
Copy the template and configure staging values:
```bash
cp ../.env.example .env
```
Edit `.env`:
```ini
UPI_FRAUD_GUARD_HOST=127.0.0.1
UPI_FRAUD_GUARD_PORT=8000
UPI_FRAUD_GUARD_REQUIRE_AUTH=true

# Generate secure tokens (minimum 32 characters)
UPI_FRAUD_GUARD_API_USERS={"admin": "STAGING_SUPER_ADMIN_TOKEN_MIN_32_CHARS_EXAMPLE_001", "analyst": "STAGING_ANALYST_TOKEN_MIN_32_CHARS_EXAMPLE_002"}

# Staging TLS certificates (Required if host is not 127.0.0.1)
UPI_FRAUD_GUARD_TLS_CERT=/etc/ssl/certs/staging_cert.pem
UPI_FRAUD_GUARD_TLS_KEY=/etc/ssl/private/staging_key.pem

# Optional CTI feeds
ABUSEIPDB_API_KEY=
OTX_API_KEY=
CTI_COLLECTION_INTERVAL_MINUTES=30
```

### Step 4: Run Verification Tests
Before starting the service, execute the full test suite in the target staging environment:
```bash
python -m unittest test_critical_remediations.py test_cti_phase2.py test_cti_phase3.py test_cti_phase4.py test_cti_phase5.py test_cti_phase6.py test_suite.py
```
*All 48 tests must pass.*

### Step 5: Start the Staging Server
```bash
python run_api.py
```
The startup process performs:
1. Security configuration validation (enforces TLS if bound to public/external IP).
2. SQLite schema creation and index verification (`risk_checks.db`).
3. Autonomous background CTI collector initialization with worker lock acquisition.

---

## 3. Staging Smoke Verification

Verify backend health and services via curl:

```bash
# 1. Health check (Unauthenticated endpoint)
curl -s http://127.0.0.1:8000/status | jq .

# 2. Authenticated Session Check
curl -s -H "Authorization: Bearer STAGING_SUPER_ADMIN_TOKEN_MIN_32_CHARS_EXAMPLE_001" http://127.0.0.1:8000/session | jq .

# 3. Pre-transaction Fraud Check (Safe baseline)
curl -s -X POST http://127.0.0.1:8000/check \
  -H "Authorization: Bearer STAGING_SUPER_ADMIN_TOKEN_MIN_32_CHARS_EXAMPLE_001" \
  -H "Content-Type: application/json" \
  -d '{"message": "Payment for groceries Rs 350", "recipient": "grocer@okaxis", "amount": 350.0}' | jq .

# 4. Multilingual Threat Check (Hindi scam alert)
curl -s -X POST http://127.0.0.1:8000/check \
  -H "Authorization: Bearer STAGING_SUPER_ADMIN_TOKEN_MIN_32_CHARS_EXAMPLE_001" \
  -H "Content-Type: application/json" \
  -d '{"message": "आपका खाता तुरंत ब्लॉक हो जाएगा। अभी अपना पिन शेयर करें।"}' | jq .
```

---

## 4. Android Client Staging Configuration

In `upi-fraud-guard-android`:
1. Open the app settings screen in debug/staging build.
2. Set the Backend API URL to the staging server endpoint (e.g., `https://staging-fraudguard.internal:8000` or `http://10.0.2.2:8000` in Android Emulator).
3. If staging has `UPI_FRAUD_GUARD_REQUIRE_AUTH=true`, enter the assigned bearer token.
4. Verify that pre-payment checks, QR scans, and notification listener detections query the staging API.
