# UPI Fraud Guard

## Current Android-focused updates

- Android supports an opt-in listener for matching payment/account notifications and a warning notification after suspicious manual checks. Android notification permission must be granted for warnings to appear.
- Android QR screen supports both live scanning and uploading an existing image. It decodes the QR on-device and checks the decoded payload through the backend.
- The message model is one shared word-and-character classifier with equally weighted English, Hindi, Marathi, and Hinglish buckets. Marathi includes a machine-translated SMS supplement and a source-grouped transfer diagnostic; this is not full-language understanding and is not native Marathi UPI validation.
- The browser dashboard has Overview and Analytics tabs. Manual risk analysis is intended to be done in the Android app; the API remains available for development.

The API now supports per-user bearer tokens, account-scoped history and deletion, and direct HTTPS configuration. Wider release still requires a real deployment, certificate/secret rotation operations, and mobile-device security review. Native-speaker-reviewed language examples must be collected with consent; none are bundled.

## Multilingual message model

`python setup.py` trains the shared message classifier on the original SMS corpus, the project's curated UPI examples, and 63,958 eligible rows derived from the ScamShield multilingual corpus. Marathi now also gets a source-group-split supplement of 3,519 machine-translated Devanagari SMS examples, trained in the same 25%-weighted Marathi bucket as the other language groups. This improves translation transfer but is not native-speaker-reviewed or UPI-specific, and does not prove natural Marathi accuracy. The external corpus contains 33,786 safe and 22,251 risky English examples, 4,725 safe and 501 risky Hindi examples, and 1,531 safe and 1,164 risky Hinglish examples. Phone numbers, email addresses, and URLs from that corpus are redacted. See `data/MULTILINGUAL_DATA_NOTES.md` for attribution, licensing notes, counts, evaluation and limitations.

The Marathi group has 3,709 training rows: 63 curated, 127 synthetic Roman-script code-mixed, and 3,519 machine-translated Devanagari examples. On a separate 938-row source-grouped translated holdout, the updated model caught 77/87 risky (88.5% recall) and alerted on 6/851 safe (0.7% false-alert rate), compared with 43/87 and 23/851 before adding translations. This diagnostic is machine-translated general SMS, not native-speaker-reviewed UPI data. External English/Hindi/Hinglish metrics and their limitations are in `data/MULTILINGUAL_DATA_NOTES.md`. These are benchmark checks, not proof of production accuracy. Review both missed scams and false alerts before real-world use. Do not treat a Safe verdict as a guarantee.

An explainable, pre-transaction UPI fraud-warning prototype. It combines three
independent signals into one final verdict:

- **Message intelligence:** the included TF-IDF + Logistic Regression model scores scam-like SMS/WhatsApp language.
- **Link and QR payload analysis:** transparent checks for shortened links, raw IP hosts, non-HTTPS URLs, risky lure words, and UPI payment payloads.
- **Transaction signals:** amount, new-recipient, frequency and time-of-day indicators.

The browser demo includes a responsive payment-check workspace, explanation of every verdict, per-module scores, and an SQLite-backed local audit trail.

## Run the demo

```bash
pip install -r requirements.txt
python run_api.py
```

Keep this terminal open while using the Android app. The API and trained models
continue running without opening the browser dashboard. The dashboard is
optional at `http://127.0.0.1:8000`; API docs are at `/api-docs`.

The default development server binds only to `127.0.0.1`; the Android emulator
uses `http://10.0.2.2:8000/`. This is local development mode, not an account
service. A non-loopback bind (for a real phone or hosted use) is refused unless
HTTPS certificate/key files and provisioned per-user API tokens are present.
Follow **API authentication, user-specific history, and deletion** below before
using a phone over a network.

## Main API

`POST /check` accepts any combination of message, `url_or_qr`, amount,
recipient, `payments_last_hour`, and `is_new_recipient`. It returns a Safe,
Suspicious, or High Risk verdict with score, reasons and module scores. The
original `/check-message` route is retained for compatibility.

## Evaluate multilingual message checks

From the repository root, run `python nlp_module/4_evaluate_multilingual.py` for the balanced 60-example regression smoke set, `python nlp_module/5_evaluate_external_holdout.py` for the separate 7,636-row public English/Hindi/Hinglish test split, and `python nlp_module/6_evaluate_marathi_translation_holdout.py` for the 938-row source-grouped machine-translated Marathi holdout. They write per-language counts and metrics under `models/`. The translated set improved Marathi transfer in this model, but it is not native-speaker-reviewed and is not an estimate of natural UPI-message accuracy. The public holdout has just 11 Hindi risky messages and no Marathi examples.

### Add consented native-language evaluation rows

No consented real-user examples are bundled. Read `data/NATIVE_LANGUAGE_DATA_COLLECTION.md`, copy the header in `data/native_language_review_template.csv` to `data/native_language_reviewed.csv`, and add only redacted, explicitly consented, native-speaker-reviewed examples. Then run:

```powershell
python nlp_module/7_evaluate_native_reviewed.py
```

This reports risky misses and safe false alerts separately per language and does not train or change the model. It also reports independent source-group counts and marks results preliminary until both classes have at least 100 examples from at least 20 independent source groups. Keep the reviewed CSV private; only aggregate metrics are written to `models/native_language_reviewed_metrics.json`.

## API authentication, user-specific history, and deletion

The local emulator development mode binds to `127.0.0.1` and may use HTTP without a token. The Android app permits this cleartext connection only to emulator host `10.0.2.2`. Do not use local development mode for a phone over Wi-Fi or for a deployed service. Any non-loopback bind is refused unless HTTPS certificate/key files and one or more provisioned per-user API tokens are configured. The user's checks and analytics are keyed to the token's configured user ID; `DELETE /history` removes only that user's saved checks. The Android Settings screen stores the token encrypted with Android Keystore and has a confirmation step before deleting history.

Generate a high-entropy token, then set these variables in the same PowerShell terminal before starting the backend. Replace the user ID, token, and certificate paths with private values and a certificate trusted by Android for the HTTPS hostname:

```powershell
$env:UPI_FRAUD_GUARD_HOST = '0.0.0.0'
$env:UPI_FRAUD_GUARD_API_USERS = '{"team-user-1":"PASTE_A_RANDOM_TOKEN_HERE"}'
$env:UPI_FRAUD_GUARD_TLS_CERT = 'C:\path\to\fullchain.pem'
$env:UPI_FRAUD_GUARD_TLS_KEY = 'C:\path\to\private-key.pem'
python -c "import secrets; print(secrets.token_urlsafe(48))"
python run_api.py
```

Run the token-generation command first and paste its output into the API-users JSON value before launching the server. Configure one unique token per user, keep the JSON in a private environment/secret manager, and never commit real tokens or private keys. Enter the HTTPS base URL and that user's token in Android **Settings**. The user's API token scopes their history; the existing Google Authenticator profile remains local and does not verify email ownership or perform self-service account registration. A production service still needs deployment hardening, protected secret storage, key rotation/revocation operations, monitoring, and review of privacy/legal requirements. Legacy rows from unauthenticated development mode remain under `local-development` and are not shared with token users.

When authentication is enabled, the browser dashboard asks for a per-user API token before loading history or analytics. It keeps the token in page memory and clears it when the page closes. Local loopback development mode does not prompt for a token.

## Transaction dataset and raw PaySim CSV

The repository includes the processed `data/transactions_dataset.csv` with
268,213 rows (260,000 normal and 8,213 fraud-labelled) and the trained
`models/transaction_model.joblib`. The model training script reads that
processed CSV. The project metadata and generator describe it as PaySim-derived.
The original raw `data/paysim.csv` (about 494 MB uncompressed) is intentionally
excluded from Git.

During normal `python setup.py`, the generator reuses the processed CSV. To rebuild from raw, obtain `paysim.csv` separately, place it in `data/`, and set `UPI_FRAUD_GUARD_REBUILD_TRANSACTIONS=1`. See `data/TRANSACTION_DATA_README.md`.

## Important prototype boundary

Message, URL, and transaction scoring use the packaged models with additional
rules for explanations and UPI payment payloads. The system is decision support;
it should not automatically approve or block a real payment. The transaction
model is based on engineered features in PaySim-derived data, not on a live
bank/UPI transaction stream.

## Setup (do this once)

Open this folder in VS Code, open a terminal (**Terminal -> New Terminal**), then run:

```
pip install -r requirements.txt
python setup.py
```

That installs everything needed and trains the model. You'll see some accuracy numbers print out -- that's it working correctly.

## Run it

```
python run_api.py
```

Open **http://localhost:8000** in a browser only if you want the web demo. The
Android app uses this same API and trained models while the dashboard is closed.

Click one of the "Try: a scam example / a safe example" buttons to auto-fill a message, or paste your own, then click **Check before paying**.

The raw API testing page (for developers, not for demoing) is at http://localhost:8000/api-docs if you ever need it.

To stop the server, click into the terminal and press `Ctrl+C`.

## Android app and API
Open `upi-fraud-guard-android` in Android Studio and run it. Start this Python
API in a separate VS Code terminal using the commands above. The API terminal
must remain running, but the browser dashboard does not. Use Android
**Settings → Save and test connection** to verify the connection. The emulator
is preconfigured for `10.0.2.2` for emulator-only loopback development. A
physical phone must use a trusted HTTPS hostname and a unique provisioned API
token; see the security section above. Plain HTTP over Wi-Fi is refused.

## If something goes wrong
Copy the error text and share it -- it's usually a missing package or a Python version issue, both quick fixes.

## What's inside (for reference, not needed to run it)
- `nlp_module/` -- the scripts that clean data and train the message-risk model
- `models/` -- the trained model, created after you run `setup.py`
- `api/` -- the server code that `run_api.py` starts (also serves the frontend)
- `frontend/` -- the demo app (index.html, style.css, script.js)
- `data/` -- the training dataset

## Current model and data status

- The API uses the packaged message, URL, and transaction model artifacts. Rules provide additional explanations and handle UPI URI payloads.
- The transaction model is trained from `data/transactions_dataset.csv`, the included processed PaySim-derived dataset (268,213 rows: 260,000 normal and 8,213 fraud-labelled). The raw `data/paysim.csv` is excluded from Git and is only read if you obtain it separately and explicitly regenerate the processed CSV.
- During normal setup the generator reuses the processed CSV. See `data/TRANSACTION_DATA_README.md`.
- Packaged metrics are evaluation snapshots, not guarantees for production or new messages. The transaction metric snapshot has precision 0.186, recall 0.6184, F1 0.286, and ROC-AUC 0.8408. Consult each JSON file and data notes for test-set limitations.
- The system is advisory and does not connect to, approve, or block live UPI payments. Keep local development mode loopback-only; use provisioned per-user tokens and HTTPS for network access.
