# UPI Fraud Guard — Android

A Kotlin/Jetpack Compose Android client for the existing UPI Fraud Guard
backend (`../api/main.py`). This does **not** replace the
Python backend or its three ML modules — it's a new front door aimed at an
individual user, in place of the browser demo, so the risk check fits into
the moment right before someone pays.

## What's here (v0.1)

- **First-run profile** — enter a name and email and verify a six-digit code
  from Google Authenticator. The secret is encrypted on the phone. This is
  local authenticator verification, not proof of email ownership or a shared
  online account.
- **Backend connection settings** — change the API address in the app and
  test `/status` before running a message or QR check. The emulator can keep
  `10.0.2.2`; a real phone requires a trusted HTTPS hostname and a provisioned
  per-user API token.
- **Check screen** — paste a message, a payment link/UPI ID, and optionally
  an amount and recipient, then get a Safe / Suspicious / High Risk verdict.
- **QR scan screen** — Google Play services' managed QR scanner with
  auto-zoom; the decoded payload is sent into the same risk-check flow.
- **QR image upload** — choose an existing QR image when camera access is
  unavailable. The QR is decoded on the device and its payload is risk-checked.
- **Result screen** — verdict, score, plain-language reasons, per-module
  scores, and parsed UPI QR payee ID, display name, amount/currency, and
  unusual-field warnings. QR parsing does not verify payee ownership; users
  are told to compare details in their payment app.
- **History screen** — checks scoped to the API token's user ID, from `GET /history`; a user can confirm deletion of their history in Settings.
- **Opt-in notification checks** — pause/resume all checks and choose Telegram,
  WhatsApp, SMS/Messages, or keyword-filtered other apps. Settings explains
  what visible notification title/text is sent and shows the last backend
  connection state. Safe results are
  saved without an alert; Suspicious and High Risk results raise an alert.
  A manual check also offers the Android notification permission and posts a
  warning when its result is Suspicious or High Risk. Alerts show a score and
  reason; tapping an alert opens the backend history details.
- **Regional-language cues** — the shared model gives English, Hindi, Marathi,
  and Hinglish each 25% of the training loss. Marathi includes 3,519
  machine-translated Devanagari SMS training examples in addition to curated
  and synthetic examples. A separate source-grouped translation holdout is
  evaluated during setup. These translations are not native-speaker-reviewed
  or UPI-specific, so native Marathi field evaluation is still needed.
- **Private QR scanning** — Google Play services handles camera permission
  and on-device scanning; the app receives only the decoded payload. The app
  uses unbundled scanner libraries to avoid bundling the native binaries that
  triggered Android's 16 KB compatibility warning. Uploaded QR images are
  decoded locally.

All screens talk to the **same FastAPI backend** that already exists in the
zip; `RiskRepository`/`RiskGuardApi` call `/check`, `/scan-qr`, and
`/history` exactly as `api/main.py` defines them.

## API security and user data

The API supports a distinct random bearer token per provisioned user. The
backend maps that token to a user ID and filters history and analytics by that
ID; `DELETE /history` deletes only that user's records. Android stores the
token encrypted using an Android Keystore key. The local Google Authenticator
profile is a separate on-device gate; it is not email verification or API
account registration. An administrator must provision the user's API token.

Local emulator development uses HTTP at `10.0.2.2` and the server's
loopback-only default. Android's network security policy permits cleartext
only to `10.0.2.2`; all other destinations require TLS. The backend refuses
non-loopback binding unless valid TLS certificate/key files and user tokens are configured. For a physical
phone or hosted deployment, use an HTTPS hostname with a certificate trusted
by Android, then enter that URL and the user's API token in Settings. Never
share a token between users or commit tokens/private keys to the project.

## Notification privacy and limits

The listener checks only while Android Notification access is enabled and the
app's master switch is on. The user can pause checks and choose sources in
Settings. Android also asks for permission to post warning notifications.
Before sending text to the backend, the app filters every selected source,
including Telegram, for payment terms or a bank/wallet warning paired with a
security action. Ordinary chat, generic links, and standalone OTP mentions
are ignored. The backend stores analyzed checks in its SQLite history and
deletes records older than 30 days. This filter reduces unrelated checks but
may still miss unusual scam wording or include a legitimate payment message.
Keep the backend on a trusted machine/network. The keyword filter can miss
scams or match legitimate alerts; the model is a warning aid, not proof that a
message is fake. Verify through the bank or UPI app directly and never share
OTPs or PINs.

## Recommended next steps

1. **On-device pre-check / caching** — Room database so recent verdicts and
   a small deny-list are available offline, and the app degrades gracefully
   without a live connection to the backend.
2. **SHAP explanation display** — the backend already returns
   `shap_explanations` (per-word/feature attribution); the Result screen
   doesn't render it yet.
3. Add history search/filters and data export that preserve per-user access.
4. Add administrator operations for token rotation/revocation and a deployed
   secret manager, then complete privacy and security review before wider use.

## Running it

1. **Start the existing backend** from the zip:
   ```
   cd ..
   pip install -r requirements.txt
   python setup.py
   python run_api.py
   ```
   The API runs at port 8000. You do not have to open the web dashboard.

2. **Set the Android app's backend address.** Open **Settings** in the app.
   For an Android **emulator**, use `http://10.0.2.2:8000/` during local
   development. For a **real phone**, use a trusted HTTPS hostname, configure
   the backend's per-user token and certificate as described in the backend
   README, and enter both the URL and issued token in app Settings. A direct
   HTTP connection over Wi-Fi is rejected by the server configuration.

3. **Open this folder in Android Studio** (Koala or newer), let Gradle
   sync, and run the `app` configuration on an emulator or device running
   Android 8.0 (API 26) or newer.

   This project uses Android Gradle Plugin 8.5.2, Gradle Wrapper 8.7, and
   Kotlin 2.0.20. It requires **JDK 17** to run Gradle. In Android Studio,
   open **File → Settings → Build, Execution, Deployment → Build Tools →
   Gradle**, keep **Distribution** set to **Wrapper**, and set **Gradle JDK**
   to JDK 17. If it is not listed, choose **Download JDK** and install version
   17. The included wrapper pins Gradle to 8.7.

## Fix a Kotlin daemon or incremental-cache build error

If Build Output shows `Daemon compilation failed`,
`IllegalArgumentException: 25.0.3`, or `Could not flush incremental caches`:

1. Stop the current build and select JDK 17 for **Gradle JDK** using the
   settings path above. Android Gradle Plugin 8.5 uses Gradle 8.7 and JDK 17.
2. Click **Sync Project with Gradle Files**, then **Build → Clean Project**,
   then **Build → Rebuild Project**.
3. If it still fails, close Android Studio, delete only this project's
   `.gradle` and `app/build` folders, reopen the Android project, sync, and
   rebuild. Gradle recreates those generated folders.

If the sync error specifically says it timed out downloading Gradle, retry
with a working connection to `downloads.gradle.org`. The wrapper uses Gradle's
direct distribution host and allows a longer download timeout. A working
internet connection to other sites does not guarantee that a school, office,
VPN, or firewall allows this download host.

This is a Gradle/JDK/cache failure, not a Kotlin source-line error. The app
project also disables Kotlin's separate compiler daemon and incremental cache
to avoid the cache-flush failure shown in Build Output.

For camera quality testing, use a real Android phone or configure the
emulator to use your computer's webcam. The emulator may show a simulated
room in its camera view; that is emulator input, not the phone camera.

## Why the split stayed this way

The report frames this as an organisation-facing fraud-detection pipeline;
this Android app reframes the *same* fusion engine as something a single
person opens before they tap "pay". Notification monitoring adds a proactive
warning path while keeping the same API and model pipeline.
