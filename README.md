# UPI Fraud Guard Enterprise v2.6.0-RC1
**AI-Driven Pre-Transaction Fraud Risk Warning System for UPI and Digital Payments**

[![Release Status](https://img.shields.io/badge/Release_Status-v2.6.0--RC1-blue.svg)](docs/deployment/RELEASE_NOTES.md)
[![Python Version](https://img.shields.io/badge/Python-3.13-brightgreen.svg)](docs/deployment/RELEASE_BASELINE.md)
[![Build & Tests](https://img.shields.io/badge/Tests-75%2F75_Passed-success.svg)](docs/testing/TESTING.md)
[![AUIE Accuracy](https://img.shields.io/badge/AUIE_FPR-0.00%25-green.svg)](docs/reports/AUIE_VALIDATION_AND_HARDENING_REPORT.md)
[![License](https://img.shields.io/badge/License-Proprietary-lightgrey.svg)](#license)

---

## 1. Project Overview & Problem Statement

Digital payment fraud across **Unified Payments Interface (UPI)** networks in India increasingly relies on social engineering, malicious payment QR payloads, phishing checkout URLs, brand impersonation, and mule account networks. 

**UPI Fraud Guard Enterprise v2.6.0-RC1** provides an autonomous, multimodal pre-transaction fraud risk warning system. It analyzes payment links, messages, QR codes, transaction amounts, and recipient VPAs **before** a transfer is authorized on a mobile device or merchant checkout.

---

## 2. Key Features

- 🌐 **Adaptive URL Intelligence Engine (AUIE):** 4-state URL classification (`CONFIRMED_MALICIOUS`, `KNOWN_BENIGN`, `SUSPICIOUS`, `UNKNOWN`) with trusted domain allowlists, IDN Punycode decoding, static HTML content parsing, and **UPI PIN solicitation threat detection**.
- 📡 **Autonomous CTI Threat Synchronization:** Background ingestion across 10 threat intelligence sources (CERT-In, NPCI, RBI, PhishTank, URLhaus, OpenPhish, CISA KEV, MITRE ATT&CK, AbuseIPDB, AlienVault OTX) with instant cache flushing.
- 💬 **Multilingual NLP Message Analysis:** Real-time urgency lure detection across 11 Indian regional languages + English using TF-IDF vectorization and Logistic Regression classifiers.
- 🕸️ **NetworkX Graph Mule Account Detection:** Graph-based fan-in/fan-out transaction velocity analysis identifying money mule accounts and fraud networks.
- 💡 **Explainable Risk Assessment:** Every risk evaluation generates a human-readable advisory, calibrated risk score, recommended user action, and technical indicator trace.
- 📱 **Android Client Application:** Modern Jetpack Compose Android app with real-time risk warnings, SMS receiver hooks, and camera barcode QR scanning.

---

## 3. Multimodal System Architecture

```text
                           [ User Input / Payment Request ]
                                          │
       ┌──────────────────────────┬───────┴──────────┬──────────────────────────┐
       ▼                          ▼                  ▼                          ▼
┌──────────────┐          ┌──────────────┐   ┌──────────────┐          ┌──────────────┐
│ Payment Link │          │  SMS / Chat  │   │ Transaction  │          │   QR Code    │
│ & URL (AUIE) │          │  Message NLP │   │ Risk Scoring │          │ Payload Scan │
└──────┬───────┘          └──────┬───────┘   └──────┬───────┘          └──────┬───────┘
       │                         │                  │                         │
       └─────────────────────────┼──────────────────┴─────────────────────────┘
                                 │
                                 ▼
                 ┌───────────────────────────────┐
                 │ Multimodal Risk Fusion Engine │
                 └───────────────┬───────────────┘
                                 │
                                 ▼
                 ┌───────────────────────────────┐
                 │  Structured Risk Advisory &   │
                 │  4-State Verdict Generation   │
                 └───────────────────────────────┘
```

---

## 4. Technology Stack

- **Backend Framework:** Python 3.13 + FastAPI, Uvicorn, Pydantic v2
- **Machine Learning:** Scikit-Learn 1.7.2, NumPy, Pandas, Joblib
- **Graph Analytics:** NetworkX 3.4
- **Database:** SQLite 3 (WAL mode) with `cti_database.py` DAO
- **Mobile Client:** Android (Kotlin 2.0.20, AGP 8.5.2, Jetpack Compose, JDK 17)
- **Security & Networking:** Certifi, Socket IP Resolution, Regex, HMAC-SHA256 Token Auth

---

## 5. Quickstart & Installation

### A. Backend Server Setup
1. **Clone Repository & Navigate to Backend:**
   ```bash
   git clone https://github.com/RS3921/AI-Driven-Pre-Transaction-Fraud-Risk-Warning-System-for-UPI-and-Digital-Payments.git
   cd upi-fraud-guard-v3
   ```
2. **Create & Activate Virtual Environment:**
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   ```
3. **Install Dependencies & Start Backend API Server:**
   ```bash
   pip install -r requirements.txt
   python run_api.py
   ```
   The backend API server runs live on [`http://127.0.0.1:8000`](http://127.0.0.1:8000) with interactive Swagger documentation at [`http://127.0.0.1:8000/api-docs`](http://127.0.0.1:8000/api-docs).

### B. Android App Setup
1. Open [`upi-fraud-guard-android`](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/upi-fraud-guard-android) in **Android Studio**.
2. Sync Gradle and run the app on an Android Emulator or physical test device.
   - Emulator default backend URL: `http://10.0.2.2:8000/`

---

## 6. Testing & Regression Verification

Execute the complete 75-test automated regression suite across all 12 test modules:

```bash
cd upi-fraud-guard-v3
python -m unittest test_payment_link_enhancement.py test_auie_security_hardening.py test_auie_expanded_benchmark.py test_auie.py test_continuous_intelligence_learning.py test_lightweight_continuous_intelligence.py test_critical_remediations.py test_cti_phase2.py test_cti_phase3.py test_cti_phase4.py test_cti_phase5.py test_cti_phase6.py test_suite.py
```
*Result:* **75 / 75 Tests Passed (100% Pass Rate)**

---

## 7. Operational Restrictions & Model Governance

> [!IMPORTANT]
> **Controlled Model Deployment Restriction:**  
> Candidate transaction model deployments are strictly locked (`Refusing model deployment: candidate lacks eligible temporal evaluation`) because the bundled PaySim dataset lacks timestamped sequential logs required for temporal cross-validation. Production models remain locked to the baseline binary (`models/transaction_model.joblib`). See [`MODEL_GOVERNANCE.md`](docs/architecture/MODEL_GOVERNANCE.md).

---

## 8. Documentation Navigation

Detailed technical documentation is organized under the [`docs/`](docs/README.md) directory:

- 🏛️ **Architecture:** [`docs/architecture/ARCHITECTURE.md`](docs/architecture/ARCHITECTURE.md) | [`CTI Architecture`](docs/architecture/CTI_ARCHITECTURE.md) | [`Model Governance`](docs/architecture/MODEL_GOVERNANCE.md)
- 💻 **Development:** [`docs/development/DEVELOPMENT_GUIDE.md`](docs/development/DEVELOPMENT_GUIDE.md) | [`Git Branching Strategy`](docs/development/GIT_BRANCHING_STRATEGY.md) | [`Roadmap`](docs/development/PROJECT_REVIEW_AND_ROADMAP.md)
- 🔒 **Security:** [`docs/security/SECURITY.md`](docs/security/SECURITY.md) | [`Security Review`](docs/security/SECURITY_REVIEW.md)
- 🧪 **Testing:** [`docs/testing/TESTING.md`](docs/testing/TESTING.md) | [`API Specs`](docs/testing/API_DOCUMENTATION.md)
- 🚀 **Deployment:** [`docs/deployment/INSTALLATION.md`](docs/deployment/INSTALLATION.md) | [`Deployment`](docs/deployment/DEPLOYMENT.md) | [`Runbook`](docs/deployment/OPERATIONS_RUNBOOK.md) | [`Release Notes`](docs/deployment/RELEASE_NOTES.md)
- 📊 **Reports:** [`Staging Validation`](docs/reports/FINAL_STAGING_VALIDATION_REPORT.md) | [`Verification`](docs/reports/FINAL_INDEPENDENT_VERIFICATION_REPORT.md) | [`AUIE Hardening`](docs/reports/AUIE_VALIDATION_AND_HARDENING_REPORT.md) | [`CTI Master Report`](docs/reports/CONTINUOUS_INTELLIGENCE_AND_CONTROLLED_LEARNING_REPORT.md)
- 📂 **Archive:** [`docs/archive/`](docs/archive/)

---

## 9. Version & License

- **Version:** `v2.6.0-RC1` (`2.6.0-Enterprise`)
- **License:** Proprietary - All Rights Reserved
