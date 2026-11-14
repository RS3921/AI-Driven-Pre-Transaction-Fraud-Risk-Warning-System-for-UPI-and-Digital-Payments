# UPI Fraud Guard Enterprise v2.6.0-RC1

[![Release Candidate](https://img.shields.io/badge/Release_Candidate-v2.6.0--RC1-blue.svg)](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/RELEASE_BASELINE.md)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/FINAL_STAGING_VALIDATION_REPORT.md)
[![AUIE Accuracy](https://img.shields.io/badge/AUIE_Precision-100%25-success.svg)](file:///C:/Users/Raveena/Downloads/UPI-Fraud-Guard/UPI-Fraud-Guard-Multilingual-Improved/AUIE_VALIDATION_AND_HARDENING_REPORT.md)
[![License](https://img.shields.io/badge/License-Enterprise-orange.svg)]()

> [!IMPORTANT]
> **Staging & Pilot Status:** **APPROVED FOR CONTROLLED PILOT WITH DOCUMENTED RESTRICTIONS**  
> *This system is approved for controlled pilot deployments under documented environment prerequisites. Do not claim unrestricted production readiness.*

---

## 1. Project Overview & System Architecture

**UPI Fraud Guard Enterprise** is an explainable, multimodal pre-transaction fraud prevention platform designed for India's Unified Payments Interface (UPI) ecosystem. It combines local machine learning classifiers, multilingual NLP (English, Hindi, Marathi, Hinglish), payment graph mule account detection, autonomous Cyber Threat Intelligence (CTI) ingestion, and an **Adaptive URL Intelligence Engine (AUIE)** to evaluate pre-payment risk in real time.

```
                          ┌──────────────────────────────────────────────┐
                          │   Android Mobile Application (Compose UI)    │
                          │  - Pre-Payment Fraud Checks & Notification   │
                          │  - Live QR Barcode Scanner & TOTP Auth       │
                          └──────────────────────┬───────────────────────┘
                                                 │ REST API (HTTPS / Bearer Auth)
                                                 ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│                             UPI Fraud Guard Enterprise Backend                              │
│                                                                                             │
│  ┌─────────────────────────┐  ┌──────────────────────────┐  ┌────────────────────────────┐  │
│  │ Multilingual NLP Engine │  │ PaySim Transaction Model │  │ Adaptive URL Intel (AUIE)  │  │
│  │ (TF-IDF + Devanagari)   │  │ (Velocity & Anomaly ML)  │  │ (4-State Classification)   │  │
│  └────────────┬────────────┘  └────────────┬─────────────┘  └─────────────┬──────────────┘  │
│               │                            │                              │                 │
│               └────────────────────────────┼──────────────────────────────┘                 │
│                                            ▼                                                │
│                              ┌──────────────────────────┐                                   │
│                              │   Risk Fusion Engine &   │                                   │
│                              │   SHAP Explainability    │                                   │
│                              └─────────────┬────────────┘                                   │
│                                            │                                                │
│  ┌──────────────────────────┐              ▼               ┌─────────────────────────────┐  │
│  │ Autonomous CTI Collector │ ◄──────────────────────────► │ SQLite Storage & WAL Engine │  │
│  │ (CERT-In, NPCI, RBI)     │                              │ (risk_checks.db)            │  │
│  └──────────────────────────┘                              └─────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Key Enterprise Features

### 🛡️ Adaptive URL Intelligence Engine (AUIE)
- **4-State Reputation Classification:** Classifies URLs into `CONFIRMED_MALICIOUS`, `KNOWN_BENIGN`, `SUSPICIOUS`, or `UNKNOWN`.
- **Zero False-Positive Target:** Built-in verified domain allowlist manager with IDN/Punycode (`xn--`) decoding and domain-vs-path user-generated content (UGC) safety checks.
- **Multi-Provider Threat Lookups:** Adapters for Google Web Risk, VirusTotal, URLhaus, OpenPhish, and AlienVault OTX with privacy parameter stripping (sensitive UPI query parameters like `pa`, `pn`, `am`, `otp` are stripped before outbound API calls).
- **Asynchronous Execution & Sub-Millisecond Cache:** Thread-pool dispatch and SQLite WAL caching deliver p95 cache hit latencies < 6.5 ms.

### 🌐 Autonomous Cyber Threat Intelligence (CTI)
- **Multi-Feed Ingestion:** Ingests live threat feeds from CERT-In Advisories, NPCI Security Circulars, RBI Fraud Awareness, PhishTank, URLhaus, OpenPhish, CISA KEV, MITRE ATT&CK, AbuseIPDB, and AlienVault OTX.
- **Fail-Closed Security Defenses:** Outbound requests enforce DNS pinning, private/loopback/cloud metadata IP blocking (`127.0.0.1`, `10.0.0.1`, `169.254.169.254`), cross-host redirect credential stripping, and 5 MiB streaming payload caps. Zero synthetic threat records are generated.

### 🗣️ Multilingual Fraud Detection & Explainability
- **Multilingual Support:** Evaluates English, Devanagari Hindi, Devanagari Marathi, and Hinglish threat patterns paired with SHAP (SHapley Additive exPlanations) feature attributions.
- **PaySim Transaction Anomaly Analysis:** Evaluates transaction velocity, recipient novelty, night-time transfer patterns, and high-value transfer anomalies.

### 📊 Analyst Operations Dashboard & Mule Account Graph
- **Interactive Dashboard:** Tabbed web UI (`http://127.0.0.1:8000`) providing Overview, AUIE URL Intelligence, Autonomous CTI Centre, Dual-Feed Threat, Mule Account Graph, and Case Investigation Queue.
- **DOM-Based XSS Defenses:** All dynamic variables are escaped with `escapeHtml()` prior to DOM insertion.

---

## 3. Installation & Quick Start

### Prerequisites
- **Python Runtime:** Python 3.10 to 3.13 (Python 3.13.14 verified)
- **Android Studio:** Ladybug / 2024.2+ (JDK 17 required)

### Step 1: Clone Repository & Enter Workspace
```bash
git clone https://github.com/RS3921/AI-Driven-Pre-Transaction-Fraud-Risk-Warning-System-for-UPI-and-Digital-Payments.git
cd AI-Driven-Pre-Transaction-Fraud-Risk-Warning-System-for-UPI-and-Digital-Payments/upi-fraud-guard-v3
```

### Step 2: Virtual Environment Setup & Dependencies
```bash
# Windows PowerShell
python -m venv venv
.\venv\Scripts\Activate.ps1

# Linux / macOS
python3 -m venv venv
source venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3: Initialize Machine Learning Models & Start API Server
```bash
# First-time initialization & model setup
python setup.py

# Start the Backend API Server
python run_api.py
```
Leave the terminal running. The backend API will bind to `http://127.0.0.1:8000`. Access the optional Analyst Dashboard in your browser at `http://localhost:8000`.

---

## 4. Environment Variables Configuration

Copy `.env.example` to `.env` in the project root:

```bash
cp .env.example .env
```

| Environment Variable | Default | Staging / Production Requirement | Description |
| :--- | :---: | :---: | :--- |
| `UPI_FRAUD_GUARD_HOST` | `127.0.0.1` | Set to host IP or `0.0.0.0` | Binding network interface address. |
| `UPI_FRAUD_GUARD_PORT` | `8000` | `8000` or `443` | Listening TCP port. |
| `UPI_FRAUD_GUARD_REQUIRE_AUTH` | `false` | Set `true` for non-loopback | Requires Bearer token authentication. |
| `UPI_FRAUD_GUARD_API_USERS` | `"{}"` | **Mandatory** if auth enabled | JSON mapping of usernames to 32+ char Bearer tokens. |
| `UPI_FRAUD_GUARD_TLS_CERT` | `""` | **Mandatory** for external binding | Path to PEM-encoded TLS certificate. |
| `UPI_FRAUD_GUARD_TLS_KEY` | `""` | **Mandatory** for external binding | Path to PEM-encoded TLS private key. |
| `GOOGLE_WEB_RISK_API_KEY` | `""` | Optional | Google Web Risk Commercial API key. |
| `VIRUSTOTAL_API_KEY` | `""` | Optional | VirusTotal API v3 key. |
| `URLHAUS_API_KEY` | `""` | Optional | URLhaus Threat API key. |
| `OPENPHISH_API_KEY` | `""` | Optional | OpenPhish Premium API key. |
| `ABUSEIPDB_API_KEY` | `""` | Optional | AbuseIPDB IP reputation key. |
| `OTX_API_KEY` | `""` | Optional | AlienVault OTX Pulses API key. |

---

## 5. Android Application Setup

1. Open `upi-fraud-guard-android` in **Android Studio**.
2. Verify **Gradle JDK** is set to **JDK 17** (**File → Settings → Build, Execution, Deployment → Build Tools → Gradle**).
3. Build and run the app on an Android Emulator or physical device.
   - **Android Emulator:** The default backend URL is `http://10.0.2.2:8000/`.
   - **Physical Device:** Set the HTTPS Backend URL and Bearer Token in **App Settings**.
4. Enable **Notification Access** for UPI Fraud Guard to enable real-time payment notification monitoring (Telegram, WhatsApp, SMS).

---

## 6. Testing & Validation Commands

Run the complete 65-test automated regression and security test suite:

```bash
cd upi-fraud-guard-v3

# Run complete 65-test suite across all 8 modules
python -m unittest test_auie.py test_auie_expanded_benchmark.py test_auie_security_hardening.py test_critical_remediations.py test_cti_phase2.py test_cti_phase3.py test_cti_phase4.py test_cti_phase5.py test_cti_phase6.py test_suite.py
```

---

## 7. Machine Learning Governance & Model Eligibility

- **PaySim Training Corpus:** Processed 268,215-row PaySim training table (`data/transactions_dataset.csv`).
- **Fail-Closed Deployment Policy:** Because `transactions_dataset.csv` lacks temporal sequence features, candidate model deployment attempts strictly fail closed (`Refusing model deployment: candidate lacks eligible temporal evaluation`), preserving active production model artifacts (`models/transaction_model.joblib`).
- **Runtime Hot-Swapping:** Approved, valid model activations update `models/active_transaction_model.json` atomically and hot-swap memory pointers without server restarts.

---

## 8. License & Security Disclaimers

- **License:** Enterprise Intellectual Property — Internal Corporate / Institutional Use.
- **Pilot Approval:** System is approved for controlled pilot deployments under documented prerequisites. Unrestricted production deployment requires mounting valid TLS certificates and provisioning commercial CTI API keys.
