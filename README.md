# UPI Fraud Guard — Android app + Python models

The Android app is the main user-facing app. It sends checks to the existing Python API, which runs the trained message, URL/QR, and transaction models. The website dashboard is optional and can remain closed. **The Python API terminal must stay running** while the Android app uses model-backed checks.

## PaySim data

The repository includes `data/transactions_dataset.csv` (the 268,213-row processed training table). The original PaySim CSV is about 494 MB and is intentionally excluded from Git. Normal setup reuses the processed table. To rebuild it from the original data, obtain `paysim.csv` separately and set `UPI_FRAUD_GUARD_REBUILD_TRANSACTIONS=1` before `python setup.py`. See `data/TRANSACTION_DATA_README.md`.

## Start the backend in VS Code (first run)

Open this folder in VS Code, open **Terminal → New Terminal**, then run:

```powershell
pip install -r requirements.txt
python setup.py
python run_api.py
```

Run those commands from the repository root. `python setup.py` installs/trains the models once. On later runs, open a new terminal in the repository root and run only:

```powershell
python run_api.py
```

Leave that terminal open. You do **not** need to open the website for the Android app to check messages or notifications. The optional dashboard is at `http://127.0.0.1:8000` on the computer.

## Connect the Android app

Open `upi-fraud-guard-android` in Android Studio, sync Gradle, and run the app.

This Android project uses Android Gradle Plugin 8.5.2, the included Gradle Wrapper 8.7, and Kotlin 2.0.20. It requires **JDK 17** for Gradle. In Android Studio, set **File → Settings → Build, Execution, Deployment → Build Tools → Gradle → Distribution** to **Wrapper** and **Gradle JDK** to JDK 17. The wrapper fetches Gradle from `downloads.gradle.org` and allows up to two minutes for the download. If the Kotlin build reports `Daemon compilation failed`, `IllegalArgumentException: 25.0.3`, or `Could not flush incremental caches`, verify those settings, sync, then run **Build → Clean Project** and **Build → Rebuild Project**. If needed, close Android Studio and remove only the Android project's `.gradle` and `app/build` generated folders before reopening.

- **Android emulator:** backend URL is already set to `http://10.0.2.2:8000/`.
- **Physical phone:** network use requires an HTTPS hostname with a certificate Android trusts, plus a per-user API token provisioned by the API administrator. Enter that HTTPS URL and token in app **Settings**. See [the backend security setup](docs/BACKEND_README.md#api-authentication-user-specific-history-and-deletion); direct HTTP over Wi-Fi is intentionally refused.

For local emulator development the backend binds to loopback and the emulator uses `http://10.0.2.2:8000/`. Network access requires both HTTPS and authentication. The browser dashboard does not need to remain open.

## Background notifications

Enable **Notification access** for UPI Fraud Guard and allow it to post alerts. Selected apps, including Telegram, are filtered before analysis: ordinary chats, generic links, and standalone OTP messages are ignored. Only payment terms or bank/wallet warnings paired with security actions are sent to the configured backend. Safe payment-related checks are saved without an alert; suspicious/high-risk results raise one. Telegram must show message previews for the app to inspect the visible text. Analyzed notification text is retained in the user's history for 30 days. The app does not read old notifications or Telegram's private chat database. The browser/dashboard does not need to be open, but the Python API process must remain running and reachable.

Risk history is scoped by the API token's user ID, retained in the backend's SQLite database for 30 days, and can be deleted from app Settings. Warnings include a risk score and reason; tapping one opens the app's history details.

## Test Telegram notification checks

Enable Telegram message previews and Android Notification access for UPI Fraud Guard. Keep the Python API running, then put UPI Fraud Guard in the background (do not force-stop it). Send a safe sample and a clearly suspicious sample from a separate test account so Telegram posts visible notifications. A normal message should not produce a UPI Fraud Guard warning; a risky result should show an alert and its matching message/reasons in **History**. Results depend on the trained model and supported-language rules, so record the actual verdict rather than assuming every sample has a fixed score.

Example safe test: “Are we still meeting at 5:30? I will bring the notes.”

Example suspicious test: “Your bank account will be blocked today. Share your OTP to receive a UPI refund.”

The shared message model combines word and character patterns and trains on the original SMS corpus, curated UPI examples, 63,958 eligible English/Hindi/Hinglish examples, 127 synthetic Marathlish examples, and 3,519 machine-translated Devanagari Marathi examples. Its classifier loss gives English, Hindi, Marathi/Marathlish, and Hinglish an equal 25% share while retaining each language group's observed safe/risky proportions. A source-grouped translated-Marathi holdout of 938 messages is kept out of training. At threshold 0.30, the updated model caught 77/87 risky translated messages (88.5% recall) and alerted on 6/851 safe ones (0.7%). Before adding translated training rows, it caught 43/87 and alerted on 23/851 in the same holdout. These are translation-transfer diagnostics—not proof of native Marathi/UPI accuracy. The translated corpus is machine-produced, not native-speaker-reviewed. Current external English/Hindi/Hinglish results and dataset limitations are documented in `data/MULTILINGUAL_DATA_NOTES.md`.

The model is one shared classifier rather than separate models for every language. Setup writes original-SMS metrics to `models/nlp_metrics.json`, external multilingual test results to `models/multilingual_external_metrics.json`, the balanced 60-example regression smoke results to `models/multilingual_eval_metrics.json`, and the translated Marathi holdout result to `models/marathi_translated_metrics.json`. The smoke set has 6 safe and 6 risky examples per language bucket; it is a regression check only, not an accuracy estimate. Marathi still needs a larger, consented, native-speaker-reviewed UPI dataset and independent native-speaker testing. Unfamiliar wording can still be missed, and false alerts can occur. A Safe result means no strong warning was found; it is not proof that a message is genuine.

UPI payment QR results show decoded payee ID, display name, requested amount/currency, and unusual or malformed fields before payment. QR decoding does not verify who owns the payee ID. Compare the displayed details with the recipient in the payment app before approving a transaction.

The listener evaluates visible notification text through the existing backend; it cannot read Telegram's private chat database or past chats. Do not use private Telegram conversations as training data without consent. For model evaluation, make a labelled, anonymized dataset with permission and compare false alarms and missed scams by language.

The app's Google Authenticator setup verifies a local time-based code during profile creation. It does not send an email OTP or verify that the email belongs to the user. Network API access uses a separate per-user token issued by the API administrator; it is not currently self-service email account registration.
