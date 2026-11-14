# SYSTEM ARCHITECTURE DOCUMENTATION

**UPI Fraud Guard Enterprise Architecture**

---

## 1. High-Level Architecture Overview

UPI Fraud Guard is an enterprise-grade payment security platform providing pre-transaction risk intelligence and decision support.

```
+-----------------------------------------------------------------------------------+
|                            MOBILE CLIENT LAYER                                   |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  | Android Native Client (Kotlin / Compose)                                    |  |
|  | - Single Activity (MainActivity) with Navigation Compose                     |  |
|  | - Hardware-backed Android Keystore Encryption (AES-GCM)                    |  |
|  | - RFC 6238 TOTP 2FA Authenticator Engine                                     |  |
|  | - Background Notification Listener Service                                   |  |
|  | - Google Play Services & ML Kit On-Device QR Scanner                        |  |
|  +-------------------------------------+---------------------------------------+  |
|                                        |                                          |
+----------------------------------------|------------------------------------------+
                                         | (HTTPS / Encrypted Bearer Token)
                                         v
+-----------------------------------------------------------------------------------+
|                             BACKEND ENGINE LAYER                                  |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  | FastAPI REST Server (Python 3.13 / Uvicorn)                                |  |
|  | - Role-Based Access Control (RBAC: Super Admin, Analyst, Investigator, Auditor)|  |
|  | - Dual-Feed Threat Intelligence Engine                                       |  |
|  | - NetworkX Graph-Based Mule Account Detector                                  |  |
|  | - Fraud Investigation Centre & Case Management Queue                          |  |
|  | - Model Drift & Statistical Population Stability Monitor                     |  |
|  +-------------------------------------+---------------------------------------+  |
|                                        |                                          |
|                                        v                                          |
|  +-----------------------------------------------------------------------------+  |
|  | Multi-Module ML Fusion Engine                                               |  |
|  | - Model 1: Multilingual Text Risk Classifier (XGBoost + TF-IDF)              |  |
|  | - Model 2: Lexical URL & Heuristic Rule Engine                                |  |
|  | - Model 3: UPI QR Payload Decoder & Transaction Velocity Engine              |  |
|  | - SHAP Explainability Engine                                                |  |
|  +-------------------------------------+---------------------------------------+  |
|                                        |                                          |
|                                        v                                          |
|  +-----------------------------------------------------------------------------+  |
|  | Database Layer (SQLite with 30-Day Automated Audit Retention)                 |  |
|  +-----------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------+
```

---

## 2. Core Subsystem Responsibilities

1. **Android Client Layer (`upi-fraud-guard-android`)**:
   - Manages user onboarding, 2FA secret generation, hardware key pair creation in Keystore.
   - Captures pre-transaction inputs (messages, URLs, UPI IDs, QR payloads).
   - Listens to incoming payment notifications via `NotificationListenerService`.

2. **Dual-Feed Intelligence Engine (`dual_feed.py`)**:
   - **Feed 1 (Transaction Intelligence)**: Evaluates velocity, amount thresholds, and recipient novelty.
   - **Feed 2 (Threat Intelligence)**: Cross-references recipient VPAs and links against 6,500+ phishing URLs and known scam VPAs.

3. **Graph-Based Mule Account Detector (`mule_detection.py`)**:
   - Builds a directed transaction graph using `NetworkX`.
   - Detects high fan-in recipient nodes (multiple unique senders transferring to one account) and circular money trails.

4. **Fraud Investigation Centre (`investigation.py`)**:
   - Registers suspicious checks into a centralized case queue (`CASE-YYYYMMDDHHMMSS-ID`).
   - Supports case status lifecycle (`New`, `Under Investigation`, `Escalated`, `Resolved`, `False Positive`), case assignment, and timeline logging.

5. **Model Performance & Drift Monitor (`model_monitor.py`)**:
   - Monitors model evaluation metrics (Precision, Recall, F1, ROC-AUC, PR-AUC).
   - Detects statistical population drift on incoming prediction distributions.
