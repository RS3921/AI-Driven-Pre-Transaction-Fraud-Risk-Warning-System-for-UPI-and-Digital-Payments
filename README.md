# UPI Fraud Guard

An explainable, pre-transaction warning prototype for UPI and digital payments. The Android app and optional browser dashboard send message, URL, QR, and manually supplied transaction signals to one local-first FastAPI service. The service scores the available signals, combines them into a risk band, explains the result, and keeps a short-lived history.

> **Prototype boundary:** UPI Fraud Guard does not connect to a bank, read account balances or recipient graphs, approve a payment, or block a payment. A Safe result means the supplied inputs did not trigger strong indicators; it is not proof that a message, link, QR, recipient, or payment is genuine.

## Contents

- [Project objective and scope](#project-objective-and-scope)
- [Features](#features)
- [Architecture and request flow](#architecture-and-request-flow)
- [Scoring methods and equations](#scoring-methods-and-equations)
- [Data sources and preparation](#data-sources-and-preparation)
- [Evaluation results](#evaluation-results)
- [Repository layout](#repository-layout)
- [Run the backend](#run-the-backend)
- [API reference](#api-reference)
- [Android application](#android-application)
- [Security and privacy](#security-and-privacy)
- [Known limitations and remaining work](#known-limitations-and-remaining-work)
- [References and attribution](#references-and-attribution)

## Project objective and scope

The objective is to give a person a clear warning before they act on a potentially fraudulent payment request. The prototype combines four kinds of evidence:

1. **Message content:** scam and social-engineering language in SMS, chat, and notification text.
2. **Link or QR payload:** lexical URL properties and fields in a UPI payment URI.
3. **Transaction context:** amount, whether the recipient is marked new, payment frequency, and time of day.
4. **A unified result:** a normalized risk score, a Safe / Suspicious / High Risk label, and short reasons.

The Android client supports manual checks, QR scanning, history, and optional notification checks. The browser dashboard is an optional local interface for history and analytics. Both use the same API and saved models.

The system is a warning aid. It does not intercept UPI apps or private chat databases, verify a payee with a bank, or make a live payment decision.

## Features

- Shared English, Hindi, Hinglish, and Marathi/Marathlish message classifier plus multilingual phrase rules.
- URL Random Forest model, transparent URL indicators, and UPI payment-URI parsing.
- Transaction Random Forest model using four behavioral features.
- Weighted fusion using only modules for which the user supplied inputs.
- Per-prediction explanations: linear-model word contributions for messages and Tree SHAP attributions for URL and transaction models.
- Android QR scan and image-pick flows; QR parsing displays payee ID, name, amount, currency, and field warnings.
- Optional Android notification listener with master pause/resume and source filters.
- Optional bearer-token authentication, per-user history and analytics, and per-user deletion.
- Saved model metrics, external multilingual holdout evaluation, and a native-language evaluation workflow.

## Architecture and request flow

~~~mermaid
flowchart LR
    A[Android app] -->|JSON check or QR payload| API[FastAPI service]
    B[Browser dashboard] -->|JSON and history requests| API
    N[Opt-in Android notification listener] -->|filtered visible notification text| API
    API --> TXT[Message model and language rules]
    API --> URL[URL model and URL indicators]
    API --> QR[UPI URI parser and QR decoder]
    API --> TX[Transaction model and rules]
    TXT --> F[Risk fusion and explanations]
    URL --> F
    QR --> F
    TX --> F
    F --> R[Verdict, score, reasons, module scores]
    R --> API
    API --> DB[(SQLite history)]
    API --> M[Saved metrics]
~~~

For a normal check, the API validates the request, scores each non-empty input, fuses the available module scores, attaches reasons and explanations, and writes the result to local history. A QR image sent to the API is size-limited, decoded in memory, and scored as a payload; the Android app can instead decode an image on-device and send only its payload.

When API authentication is enabled, the bearer token identifies the user before history is read or written. History, analytics, and deletion are scoped to that user ID.

| Component | Implementation | Output |
| --- | --- | --- |
| Message | Word and character TF-IDF + Logistic Regression; multilingual rules; explicit-safe-context cap | Message score, phrase reasons, top word contributions |
| URL | URL lexical features + Random Forest; readable indicators | URL score, structural reasons, top Tree SHAP features |
| UPI QR | URI parser and field checks; no payee ownership lookup | Payload score, parsed payee/payment fields, anomaly flags |
| Transaction | Four numeric/boolean features + class-weighted Random Forest | Transaction score, context reasons, top Tree SHAP features |
| Fusion | Weighted average over supplied modules plus multi-signal risk floor | Final score, verdict, modules, combined reasons |
| API and storage | FastAPI, Pydantic, SQLite | Validation, authentication, endpoints, 30-day history |
| Clients | Kotlin/Jetpack Compose Android app and static browser dashboard | Manual checks, QR flows, notifications, history, analytics |

## Scoring methods and equations

### Message classifier

The text model uses a scikit-learn FeatureUnion:

- **Word TF-IDF:** lowercased unigrams and bigrams, up to 12,000 features.
- **Character TF-IDF:** lowercased character n-grams of lengths 3–5 within word boundaries, up to 20,000 features.
- Both vectorizers use sublinear term frequency and minimum document frequency 2.
- Logistic Regression with L2 regularization estimates the probability of a risky label.

For message vector **x**, the raw probability is:

~~~text
z = w · x + b
p_model = sigmoid(z) = 1 / (1 + exp(-z))
~~~

A simplified view of the term weighting is:

~~~text
tfidf(t, d) = (1 + log(tf(t, d))) × (1 + log((1 + N) / (1 + df(t))))
~~~

The vectorizer then applies its configured normalization. Here, **tf** is a term count in a message, **df** is the number of messages containing the term, and **N** is the training-message count.

The training set gives English, Hindi, Marathi/Marathlish, and Hinglish equal total sample weight while preserving each language group's observed safe/risky ratio. If **M** is the total training-row count and **N_g** is the row count for language group **g**, each row in that group receives weight **M / (4 × N_g)**. Thus, each language group accounts for one quarter of the weighted loss; this does **not** make evidence quality or coverage equal across languages.

At inference, an explicit-safe-context rule caps model-only suspicion at **0.22** for recognized routine notices or safety advice. Multilingual rules identify credential requests, payment lures, urgency, account threats, and related cues. The message score is the greater of the capped model probability and applicable rule score. Rules can still raise risk if a message contains an active scam cue.

The original-corpus metrics use the plain classifier threshold **0.50**. API/notification comparisons use the combined score threshold **0.30**.

### URL model

The URL classifier is a Random Forest with 200 trees and maximum depth 12. The URL list is split into stratified training and test sets; only the training portion is majority-undersampled, leaving the test distribution intact. The model predicts the risky-class probability:

~~~text
p_url = (1 / T) × sum(tree_probability_t(risky | x))
~~~

The 12 model features are URL length, number of dots/hyphens/digits/subdomains, IP-host flag, at-sign flag, known-shortener flag, suspicious-TLD flag, path length, suspicious-keyword count, and digit ratio.

HTTPS is deliberately **not** a model feature. The project's older legitimate-URL data and newer phishing snapshots differ in HTTPS adoption, which caused a misleading shortcut during model development. Non-HTTPS remains a readable warning reason, but does not directly change the Random Forest score.

URL analysis is lexical: it does not visit the destination, execute scripts, or verify current domain reputation at request time. The model uses bundled URL snapshots; it does not fetch a fresh threat feed during a check.

### UPI payment QR payload

A parsed **upi://pay** URI can expose **pa** (payee VPA), **pn** (display name), **am** (amount), **cu** (currency), **mc** (merchant code), **tn** (note), and **tr/tid** (reference).

Current rule scores:

- **0.12** when the URI parses and no unusual fields are flagged.
- **0.42** when fields need caution but the payload is structurally well formed.
- **0.78** when the URI is malformed or has a structural anomaly.

Flags include a missing or unusual VPA format, duplicate fields, malformed amount/currency, control characters in a name, or an amount of ₹10,000 or more. Missing currency is displayed as an INR assumption without raising risk by itself.

Parsing only establishes that fields can be read. It does not establish that the VPA belongs to the displayed person or merchant. Verify payee and amount in the payment app.

### Transaction model

The Random Forest uses four features: amount, new-recipient flag, payments in the last hour, and **is_night** (1 for local hours 23:00–05:59, otherwise 0). It has 200 trees, maximum depth 8, and class_weight="balanced". Its score is the average risky-class probability from the trees:

~~~text
p_transaction = (1 / T) × sum(tree_probability_t(risky | x))
~~~

The model was trained on the processed PaySim-derived table. Amount, recipient status, and recent frequency are manually supplied; the app does not read them from a bank. Readable rules provide context reasons, but the trained model supplies the score. The transaction module is omitted when its inputs are all blank so an empty form is not treated as a zero-value transaction.

### Risk fusion

Only modules with a score are included. The configured weights are:

| Module | Weight |
| --- | ---: |
| Message | 0.40 |
| URL or UPI QR payload | 0.35 |
| Transaction | 0.25 |

For available module set **A**, score **r_m**, and configured weight **λ_m**:

~~~text
R_weighted = sum(λ_m × r_m for m in A) / sum(λ_m for m in A)
~~~

If two or more supplied module scores are at least **0.65**, the combined result is raised to at least **0.72**. The final score is capped at **0.99** and rounded to three decimal places.

~~~text
Safe        : R < 0.30
Suspicious  : 0.30 ≤ R < 0.65
High Risk   : R ≥ 0.65
~~~

With one module, normalization makes the final score equal to that module's score. The weights and thresholds are prototype policy choices; they have not been calibrated against a production UPI population.

### Explanations and evaluation measures

Message attributions use the exact linear-model feature contribution **coefficient × TF-IDF value** for active features, returning up to four largest absolute contributions. URL and transaction attributions use SHAP TreeExplainer for the risky class and return up to four largest absolute feature contributions. Readable rule reasons are kept separate from model attribution: a reason names a recognizable indicator, while an attribution describes which model features moved that particular prediction.

~~~text
precision = TP / (TP + FP)
recall    = TP / (TP + FN)
F1        = 2 × precision × recall / (precision + recall)
~~~

**TP** is a risky example correctly flagged, **FP** a safe example flagged as risky, and **FN** a risky example missed. ROC-AUC summarizes ranking across thresholds; it does not select a safe operational threshold by itself.

## Data sources and preparation

All text labels use **0 = safe/legitimate** and **1 = risky/spam/phishing**. Bundled files contain public, curated, synthetic, translated, or simulator-derived examples—not messages collected from project users.

### Message data

| Source / file | Rows used | Role and limitations |
| --- | ---: | --- |
| SMS Spam Collection, cleaned as data/messages_clean.csv | 4,457 training + 1,115 untouched test | Original English SMS ham/spam corpus. Stratified split uses test_size=0.2, random_state=42. General SMS spam, not a UPI-specific benchmark. |
| data/message_training_additions.csv | 306 | Curated UPI-oriented examples; training only. |
| ScamShield, data/multilingual_training_subset.csv | 63,958 | English, Hindi, Hinglish smishing/social-engineering rows after source filtering, exact-text deduplication, and redaction of phone-like numbers, emails, and URLs. |
| data/marathi_synthetic_supplement.csv | 127 | Roman-script Marathi-English/Marathlish examples for training only; many source rows are explicitly unreviewed. |
| data/marathi_translated_training.csv | 3,519 | Devanagari Marathi translated from English SMS; supplemental training, not native-speaker-written/reviewed or UPI-specific. |
| **Total message-model training rows** | **72,367** | 60,683 English, 5,269 Hindi, 2,706 Hinglish, and 3,709 Marathi/Marathlish rows; weighted loss is 25% per group. |

### Message evaluation sets

| Evaluation set | Size and support | What it can show |
| --- | --- | --- |
| Original SMS holdout | 1,115 English examples | Stratified holdout from the original corpus; never used for training. |
| ScamShield external test | 7,636: English 7,069; Hindi 460; Hinglish 107 | Separate source test split after overlap filtering. Only 11 Hindi risky and 12 Hinglish safe examples; class-specific rates for those groups are unstable. No Marathi examples. |
| Translated-Marathi holdout | 938: 851 safe, 87 risky | Grouped by original English SMS to avoid train/test source overlap. Translation-transfer diagnostic, not native Marathi field evaluation. |
| Curated multilingual smoke set | 60: 12 each in English, Hindi, Marathi, Hinglish, and Marathlish | Six safe and six risky examples per group. Regression check only, not an accuracy estimate. |

See [data/MULTILINGUAL_DATA_NOTES.md](data/MULTILINGUAL_DATA_NOTES.md) for corpus attribution, split design, counts, evaluation, and limitations. The project has no consented, native-speaker-reviewed real-user examples. [data/NATIVE_LANGUAGE_DATA_COLLECTION.md](data/NATIVE_LANGUAGE_DATA_COLLECTION.md) documents a controlled workflow and blank template; do not commit completed participant-message rows.

### URL and QR data

The URL model combines snapshots in data/real_url_lists/: an academic legitimate/phishing URL collection, modern legitimate root domains, an OpenPhish snapshot, and a PhishTank verified-phishing snapshot. The trainer removes exact duplicate URLs, uses a stratified 80/20 split with random_state=42, and undersamples only the phishing-majority training side to a 2:1 majority/minority ratio. The test portion is not undersampled.

OpenPhish and PhishTank files are dated snapshots, not live reputation services. Feed policies and licenses vary; review upstream terms before redistributing or using commercially. The QR parser uses fields in a UPI URI and does not query a bank or payee registry.

### Transaction data

data/transactions_dataset.csv contains **268,213 rows**: 260,000 normal and 8,213 fraud-labelled transactions. The data are PaySim simulator-derived mobile-money records, not real UPI user histories. The raw PaySim CSV is about 494 MB and is intentionally not stored in this repository; the processed table is enough to retrain the model. See [data/TRANSACTION_DATA_README.md](data/TRANSACTION_DATA_README.md).

The generator maps PaySim fields as follows:

- Amount comes from the simulator transaction amount.
- hour_of_day is PaySim step modulo 24.
- is_new_recipient marks the first occurrence of a sender/destination pair.
- payments_last_hour counts other transactions by the same sender in the same PaySim step.
- The model derives is_night from hour_of_day and retains amount, recipient status, and frequency.

The transaction trainer uses a stratified 80/20 split with random_state=42 and compares baseline, class-weighted, and SMOTE strategies on training data. The packaged model is the class-weighted Random Forest. Optional IEEE-CIS research metrics are in models/ieee_cross_validation_metrics.json. IEEE-CIS is card/e-commerce data, not peer-to-peer UPI transfers; its feature mapping is only an approximation.

## Evaluation results

These are saved results in models/ at the time this README was written. They are dataset-specific experiments, not a guarantee of real-world performance or threshold calibration for UPI traffic.

| Model / evaluation | Samples | Precision | Risky recall | F1 | ROC-AUC | Interpretation |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Message classifier, original holdout, threshold 0.50 | 1,115 | 0.9650 | 0.9262 | 0.9452 | 0.9964 | Original English SMS corpus. |
| Combined message model + rules, same holdout, threshold 0.30 | 1,115 | 0.9051 | 0.9597 | 0.9316 | — | Higher recall at API threshold, with lower precision on this split. |
| URL Random Forest, bundled URL holdout | 1,737 | 0.9837 | 0.8795 | 0.9287 | 0.9587 | Snapshot-derived; future campaigns may differ. |
| Transaction Random Forest, PaySim-derived holdout | 53,643 | 0.1860 | 0.6184 | 0.2860 | 0.8408 | **Low precision:** many positive alerts are false alerts on this split. Needs better data and calibration. |
| External English messages | 7,069 | 0.9301 | 0.9758 | 0.9524 | — | Safe false-positive rate 4.72%. |
| External Hindi messages | 460 | 0.8889 | 0.7273 | 0.8000 | — | Only 11 risky examples; unstable recall. Safe false-positive rate 0.22%. |
| External Hinglish messages | 107 | 0.9694 | 1.0000 | 0.9845 | — | Only 12 safe examples; unstable. Safe false-positive rate 25.0%. |
| Machine-translated Marathi holdout | 938 | 0.9277 | 0.8851 | — | — | 77/87 risky caught; 6/851 safe flagged. Not native Marathi evaluation. |
| Curated multilingual smoke set | 60 | 1.0000 | 1.0000 | — | — | Six safe and six risky per group; regression check only. |

The Marathi holdout is machine-translated English SMS, not native-speaker-reviewed Marathi UPI traffic. The smoke set is deliberately small and curated; its perfect result is not an independent benchmark.

The transaction model's PaySim metrics show a precision/recall trade-off and especially poor precision. The recorded IEEE-CIS comparison further documents domain shift: the PaySim-trained model achieved ROC-AUC 0.4812 and recall 0.0029 on that cross-domain experiment. IEEE-CIS has card transactions and no true UPI recipient field. This is evidence of a limitation, not cross-domain readiness.

Useful evaluation commands, from the repository root:

~~~powershell
python nlp_module/4_evaluate_multilingual.py
python nlp_module/5_evaluate_external_holdout.py
python nlp_module/6_evaluate_marathi_translation_holdout.py
python nlp_module/7_evaluate_native_reviewed.py
~~~

The native-reviewed evaluator expects a private, consented input file; it does not train the model. Do not add completed private evaluation rows to public source control.

## Repository layout

~~~text
.
├── api/                         FastAPI routes, validation, authentication
├── data/
│   ├── real_url_lists/          Bundled URL list snapshots
│   ├── messages_clean.csv       Clean original SMS corpus
│   ├── multilingual_*.csv       Filtered train, holdout, and smoke data
│   ├── marathi_*.csv            Translation/synthetic supplements and split
│   └── transactions_dataset.csv Processed PaySim-derived training rows
├── docs/
│   ├── BACKEND_README.md
│   ├── PROJECT_REVIEW_AND_ROADMAP.md
│   └── UPI_Fraud_Guard_Project_Progress_Report.docx
├── frontend/                    Optional browser dashboard
├── models/                      Saved estimators and JSON metrics
├── nlp_module/                  Text preparation, training, evaluation
├── transaction_module/          Features, training, transaction evaluation
├── url_qr_module/               URL features, QR parsing, training
├── upi-fraud-guard-android/     Android Studio project
├── multilingual_message_rules.py
├── risk_fusion.py
├── shap_explainability.py
├── requirements.txt
├── setup.py                     Full model preparation/training pipeline
└── run_api.py                   Local API and dashboard entry point
~~~

## Run the backend

The repository includes trained model artifacts and processed training tables. To use the saved models, you do **not** need to retrain first.

### Requirements

- Python 3.10 or newer; Python 3.12 is used by the development runtime.
- Windows, macOS, or Linux. Commands below use Windows PowerShell.
- Internet access for the initial Python package installation.
- The exact scikit-learn version in requirements.txt, 1.7.2, because joblib model files can be version-sensitive.

### Install and start

From the repository root:

~~~powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python run_api.py
~~~

The default server binds only to 127.0.0.1:8000. Open:

- Dashboard: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- Health/status: [http://127.0.0.1:8000/status](http://127.0.0.1:8000/status)
- Interactive API docs: [http://127.0.0.1:8000/api-docs](http://127.0.0.1:8000/api-docs)

Keep the API process running while using the dashboard or Android app.

### Retrain the packaged models

Only retrain when intentionally regenerating model files and metrics. From the repository root, after installing requirements:

~~~powershell
python setup.py
~~~

The setup script prepares multilingual splits, trains the text model, runs text evaluations, trains the URL model, prepares/reuses the transaction table, and trains the transaction model. It writes to models/ and may update generated files under data/. Keep copies of model files if comparing training changes. The raw PaySim CSV is not needed when the processed transaction table is present.

## API reference

The full schemas are available at /api-docs. Main routes:

| Method | Route | Purpose |
| --- | --- | --- |
| GET | /status | Health, version, authentication state, feature list |
| GET | /session | Current local or authenticated user identity |
| POST | /check | Score supplied message, URL/QR, and/or transaction inputs |
| POST | /check-message | Compatibility alias for a message check |
| POST | /scan-qr | Decode and score an uploaded QR image, limited to 5 MB |
| GET | /history | Read current-user history; supports time bounds and capped limit |
| DELETE | /history | Delete current-user history |
| GET | /analytics | Risk counts, average score, and time-series buckets |
| GET | /model-metrics | Saved model and evaluation metrics |

Example POST /check request:

~~~json
{
  "message": "Your bank account will be blocked today. Share your OTP for a refund.",
  "url_or_qr": "https://example.invalid/verify",
  "amount": 15000,
  "recipient": "merchant@example",
  "payments_last_hour": 3,
  "is_new_recipient": true
}
~~~

Every field is optional, but at least one message, URL/QR value, or transaction detail is required. Inputs are range-checked. The response includes risk_score, verdict, reasons, modules_used, per-module scores, per-module feature attributions, and parsed UPI QR details when applicable. Do not submit real OTPs, PINs, passwords, or sensitive account details.

The history route accepts limit (bounded to 1–5,000) and ISO-8601 start/end filters. Analytics accepts a preset days window or explicit start/end range. Records older than 30 days are pruned.

## Android application

Open upi-fraud-guard-android/ as the project in Android Studio. The included Gradle wrapper is 8.7, Android Gradle Plugin is 8.5.2, Kotlin is 2.0.20, and the app targets Android 8.0 / API 26 or newer. Use JDK 17 as the Gradle JDK. See [the Android guide](upi-fraud-guard-android/README.md) for build troubleshooting and user flows.

For an Android emulator, the backend URL is http://10.0.2.2:8000/; this routes from the emulator to the development computer. The backend still binds to loopback. A physical phone needs a trusted HTTPS hostname, a network-reachable deployment, and a provisioned user token. Do not switch the development API to an unauthenticated network bind.

Notification monitoring is opt-in. It reads visible notification title/text only while Android notification access and the app's monitoring switch are enabled. It filters notifications before sending matching payment-related text to the API. It cannot read private Telegram/WhatsApp databases or old notification history. The app's Google Authenticator setup verifies a TOTP code locally; it is not email ownership verification, server-side account registration, or API authentication.

## Security and privacy

- The development API is loopback-only by default. run_api.py refuses non-loopback binding unless API users and both TLS certificate/key paths are configured.
- For authenticated network mode, set UPI_FRAUD_GUARD_HOST, UPI_FRAUD_GUARD_API_USERS, UPI_FRAUD_GUARD_TLS_CERT, and UPI_FRAUD_GUARD_TLS_KEY. The JSON maps a user ID to a unique random bearer token of at least 32 characters. Use a private environment or secret manager; never commit real tokens, private keys, or .env files.
- Generate a random token with Python: python -c "import secrets; print(secrets.token_urlsafe(48))". Configure a unique token per user and deliver it securely.
- The API hashes tokens before comparison and uses constant-time digest comparison. In authenticated mode, the token's configured user ID scopes history, analytics, and deletion.
- Without network authentication, local checks use the shared local-development identity. Keep that mode on loopback.
- History is stored in data/risk_checks.db; the API retains entries for 30 days and stores at most the first 1,000 characters of message and URL fields.
- QR uploads are limited to 5 MB and are decoded in memory; uploaded images are not written to the audit database.
- The Android app encrypts its API token and TOTP secret with Android Keystore. This does not replace a device-security review.
- The SQLite file and raw PaySim file are ignored for new commits. The processed transaction table and public/curated model data remain in the repository.

Example PowerShell configuration for a private HTTPS deployment (replace all placeholders; never commit real values):

~~~powershell
$env:UPI_FRAUD_GUARD_HOST = '0.0.0.0'
$env:UPI_FRAUD_GUARD_API_USERS = '{"team-user-1":"PASTE_A_RANDOM_TOKEN_HERE"}'
$env:UPI_FRAUD_GUARD_TLS_CERT = 'C:\path\to\fullchain.pem'
$env:UPI_FRAUD_GUARD_TLS_KEY = 'C:\path\to\private-key.pem'
python run_api.py
~~~

The TLS certificate must be trusted by Android for the hostname. Network mode is not a production deployment recipe by itself; add firewall restrictions, monitoring, token rotation/revocation, backup and recovery, and security/privacy review before real users.

## Known limitations and remaining work

### Model and data

- The transaction model has low precision (0.186 on its packaged holdout); alerts need threshold calibration and better representative data before operational use.
- New-recipient and recent-frequency inputs are user-entered. There is no real account, recipient graph, or bank feed.
- Marathi additions are machine-translated general SMS plus a small synthetic supplement. There is no independent external Marathi test set or consented native-speaker-reviewed field set.
- Hindi risky and Hinglish safe evaluation supports are small. The perfect smoke-set scores are not evidence of generalization.
- URL snapshots and labels may be stale, duplicated upstream, or source-biased. The URL model does not resolve links or check a live threat-intelligence feed.
- No end-to-end fusion benchmark shows that the combined score improves outcomes for real UPI users.
- There is no automated drift monitoring, retraining approval, rollback, or continuous evaluation service.

### Product and deployment

- The system warns but does not stop a transaction or verify a recipient with a payment provider.
- Notification checks depend on Android permissions, visible previews, selected sources, and the user keeping monitoring enabled.
- The Android result view does not yet render backend per-feature attributions.
- The TOTP profile is a local setup gate, not server-side account or email verification.
- Production deployment still needs managed secrets, token issuance/rotation/revocation, observability, security testing, privacy review, and field evaluation.

See [docs/PROJECT_REVIEW_AND_ROADMAP.md](docs/PROJECT_REVIEW_AND_ROADMAP.md) for project status and [docs/UPI_Fraud_Guard_Project_Progress_Report.docx](docs/UPI_Fraud_Guard_Project_Progress_Report.docx) for the written progress report.

## References and attribution

- [ScamShield: Multilingual Smishing & Social Engineering Corpus](https://huggingface.co/datasets/sidzzz07/scamshield-dataset) — source note records the snapshot revision and declared MIT license.
- [Indian Scam SMS (synthetic, audited)](https://huggingface.co/datasets/Ridham115/indian-scam-sms-synthetic-audited) — source note records declared CC BY 4.0 and review caveats.
- [OpenPhish](https://openphish.com/) and [PhishTank](https://phishtank.org/) — bundled snapshots are used for URL training; they are not queried at runtime.
- [PaySim](https://www.kaggle.com/datasets/ealaxi/paysim1) — simulated mobile-money source; only the processed table is in this repository, not the approximately 494 MB raw CSV.
- Counts, transformations, split design, and source caveats are documented in [data/MULTILINGUAL_DATA_NOTES.md](data/MULTILINGUAL_DATA_NOTES.md), [data/TRANSACTION_DATA_README.md](data/TRANSACTION_DATA_README.md), and the training scripts. Review upstream terms before redistribution or commercial use.
