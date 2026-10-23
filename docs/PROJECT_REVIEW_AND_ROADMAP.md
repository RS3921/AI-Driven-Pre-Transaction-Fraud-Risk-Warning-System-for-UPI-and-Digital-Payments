# UPI Fraud Guard: current state and next steps

## Current project

The Android client and optional browser dashboard use one Python FastAPI backend. The API combines message scoring, URL/QR analysis, transaction signals, and risk fusion. It stores check history in SQLite and removes records after 30 days. The Android app provides manual checks, QR scanning/upload, notification monitoring, settings, and history.

The app is a warning aid. It does not connect to, approve, or block a live UPI payment. A low score cannot prove that a message or payee is safe.

## Highest-priority status

1. **QR warnings — implemented.** The app parses UPI payment QR fields, including payee ID, display name, amount, and currency, and shows them on the result before payment. Missing or malformed fields, duplicate fields, and unusual amounts/currencies are flagged. QR details and reasons also appear in history. The app explicitly says it does not verify payee ownership.
2. **Real-world language testing — workflow implemented; data collection remains.** The evaluator reports risky misses, safe false alerts, and independent source-group support separately by language. It excludes unconsented, unreviewed, malformed, and exact training-duplicate rows. The team must still collect consented, redacted, native-speaker-reviewed examples. No such field data is fabricated or bundled.
3. **Notification controls — implemented.** Settings includes a master pause/resume switch and source toggles for Telegram, WhatsApp, Messages, and other keyword-matched apps. It explains what visible notification text is sent and records whether the last background check reached the backend. Android Notification Access must remain enabled in system settings.
4. **Data protection — prototype controls implemented.** Non-loopback API binding requires HTTPS and configured per-user tokens; checks, history, and analytics are user-scoped; the app encrypts its API token with Android Keystore; users can delete their history; and Android cleartext traffic is limited to the emulator development host. Production account enrollment, token rotation/revocation operations, monitoring, encrypted server storage, and privacy/security review remain necessary before wider release.

## Language review workflow

Read `data/NATIVE_LANGUAGE_DATA_COLLECTION.md`, copy the header in `data/native_language_review_template.csv` to a private `data/native_language_reviewed.csv`, then add only consented, redacted, approved native-speaker examples. Run `python nlp_module/7_evaluate_native_reviewed.py` from the repository root. The evaluator writes aggregate metrics only and does not retrain the model. Aim for at least 100 safe and 100 risky examples, from at least 20 independent source groups in each class, per language. Smaller samples are labeled preliminary.

The existing Marathi supplement is machine-translated and must not be described as native-reviewed. More rows alone do not prove better performance; review false alerts and missed scams separately.

## Important deployment limits

Local Android emulator development uses `http://10.0.2.2:8000/` while the Python API binds only to computer loopback. Physical-phone/network use requires a trusted HTTPS hostname/certificate and a unique provisioned API token for each user. Do not expose the local development server over plain HTTP. The current Google Authenticator profile is local onboarding; it is not email ownership verification or API account enrollment.

The token-based user boundary is for a prototype, not a completed production security review. Before a public service, add protected secret management, token rotation/revocation workflows, rate limits, monitoring, backup/restore policy, encrypted server storage, and privacy/legal review. API tokens are provisioned by an administrator and are separate from the local profile.

## Other useful work still open

- **Production identity/account lifecycle:** add secure account enrollment, token rotation/revocation UI, and connect app profile identity after choosing an identity provider.
- **History usability:** add search and filters by date, source app, risk level, and message versus QR.
- **User feedback:** allow optional reports of false alarms and missed scams with explicit consent and a review queue; never silently add private messages to training.
- **Release validation:** establish automated Android/API build checks and a device test plan for QR scan/upload, camera, permissions, notifications, invalid tokens, history deletion, TLS, weak connections, and different phone models.
- **Away-from-computer use:** deploy a secured hosted API or evaluate supported on-device models. Model-backed checks still need the Python API to be reachable.

## Data handling notes

- Do not put a populated `data/risk_checks.db`, private tokens, TLS private keys, or the consented evaluation CSV in a public repository or distributable project archive.
- Remove personal information and secrets from evaluation examples before review; keep the working file in controlled storage and delete it when its approved evaluation period ends.
- Avoid calling machine-translated examples native Marathi or claiming model certainty from small or curated test sets.

## Patent preparation note

Feature lists alone do not establish patentability. Document the team's specific technical contribution, search relevant prior art, and obtain advice from a registered patent professional before public disclosure. This is not a patentability opinion.
