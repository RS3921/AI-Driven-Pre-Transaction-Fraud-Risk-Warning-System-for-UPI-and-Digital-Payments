# UPI Fraud Guard Enterprise: Current State & Product Roadmap

**Current Release Designation:** `v2.6.0-RC1` (`2.6.0-Enterprise`)  
**Status:** Approved for Controlled Pilot with Documented Restrictions  
**Primary Subprojects:**
- Backend Platform: `upi-fraud-guard-v3`
- Android Application: `upi-fraud-guard-android`

---

## 1. Current System Capabilities (v2.6.0-RC1 Completed Milestones)

The current enterprise platform integrates multimodal pre-transaction fraud prevention across Android and server components:

1. **Adaptive URL Intelligence Engine (AUIE) — COMPLETED:**
   - Replaced legacy keyword penalties with a 4-state classification model (`CONFIRMED_MALICIOUS`, `KNOWN_BENIGN`, `SUSPICIOUS`, `UNKNOWN`).
   - Integrated verified domain allowlist manager with Punycode/IDN (`xn--`) decoding and user-generated content path safety checks.
   - Built multi-provider adapters (Google Web Risk, VirusTotal, URLhaus, OpenPhish, AlienVault OTX) with sensitive query parameter privacy stripping.
   - Asynchronous thread-pool execution and SQLite WAL caching deliver p95 cache hit latencies < 6.5 ms.
   - Eliminates false positives on legitimate banking, payment, and commercial portals (0.00% FPR across 700 legitimate benchmark samples).

2. **Autonomous Cyber Threat Intelligence (CTI) Engine — COMPLETED:**
   - Ingests, normalizes, deduplicates, and validates threat indicators from 10 Indian and global feeds (CERT-In, NPCI, RBI, PhishTank, URLhaus, OpenPhish, CISA KEV, MITRE ATT&CK, AbuseIPDB, AlienVault OTX).
   - Enforces strict SSRF defenses: DNS pinning, loopback/private IP blocking (`127.0.0.1`, `10.0.0.0/8`, `169.254.169.254`), cross-host redirect credential stripping, and 5 MiB streaming byte caps.
   - Zero synthetic/mock indicator fallbacks.

3. **Multilingual Fraud Detection & Explainability — COMPLETED:**
   - Shared multilingual NLP classifier (English, Devanagari Hindi, Devanagari Marathi, Hinglish) paired with SHAP feature attributions.
   - PaySim transaction anomaly ML classifier for transfer velocity, new payee detection, and circadian transfer patterns.

4. **Android Client Application — COMPLETED:**
   - Android Jetpack Compose UI (AGP 8.5.2, Kotlin 2.0.20, JDK 17).
   - Live camera QR barcode decoder and `upi://pay` URI parser.
   - Background notification monitor with app filtering (Telegram, WhatsApp, Messages).
   - Local Google Authenticator TOTP onboarding and Keystore-encrypted token storage.

5. **Analyst Operations Dashboard & Investigation Queue — COMPLETED:**
   - Web dashboard (`http://127.0.0.1:8000`) featuring Overview, AUIE URL Intelligence, Autonomous CTI Centre, Dual-Feed Threat, Mule Account Graph, and Case Investigation Queue.
   - Strict DOM-based XSS sanitization (`escapeHtml()`) across all untrusted backend text fields.

---

## 2. Product Roadmap & Open Next Steps

### Phase A: Controlled Pilot & Field Operations (Q1 2027)
- **Physical Device QR Camera Field Testing:** Perform field testing across physical Android handsets (Samsung, Xiaomi, OnePlus, Pixel) to verify PyZBar camera barcode decoding in low-light and distorted QR conditions.
- **Commercial CTI Provider Credentials:** Inject commercial API keys (`GOOGLE_WEB_RISK_API_KEY`, `VIRUSTOTAL_API_KEY`, `OTX_API_KEY`) into staging/production `.env` configuration.
- **TLS Certificate Infrastructure:** Mount production PEM-encoded TLS certificates (`UPI_FRAUD_GUARD_TLS_CERT`, `UPI_FRAUD_GUARD_TLS_KEY`) when binding server to non-loopback network interfaces.

### Phase B: Enterprise Scale & Identity Lifecycle (Q2 2027)
- **PostgreSQL Database Migration:** Transition SQLite storage to PostgreSQL when write throughput exceeds 500 checks/second in multi-worker cluster deployments.
- **Production OAuth2/OIDC Identity Provider:** Replace admin-provisioned Bearer tokens with OAuth2/OpenID Connect (Okta/Keycloak) user sign-in and token rotation/revocation workflows.
- **Dynamic Shortener Expansion:** Expand shortened links (`bit.ly`, `tinyurl.com`, `cutt.ly`) asynchronously to inspect final destination host reputations before risk scoring.

---

## 3. Data Protection & Security Policy

- **No Synthetic Intelligence:** Synthetic or mock threat indicators are strictly forbidden in production database tables.
- **Privacy Parameter Stripping:** Outbound provider lookups must strip sensitive payment fields (`pa`, `pn`, `am`, `otp`, `pin`, `token`) prior to network transmission.
- **Retention & Compliance:** Pre-transaction check records are retained in SQLite for 30 days and purged automatically via database retention policies.
