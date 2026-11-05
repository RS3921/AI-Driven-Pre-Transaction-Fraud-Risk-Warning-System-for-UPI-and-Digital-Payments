# UPI Fraud Guard for Android

UPI Fraud Guard is a Kotlin Android client for checking suspicious payment messages, links, and QR payloads. It uses a single Activity with Jetpack Compose screens and a separately configured FastAPI service for risk scoring and account history.

## Architecture

```text
Compose UI (MainActivity, screens)
  ├─ CheckViewModel
  ├─ NotificationListenerService ── keyword filter ──┐
  ├─ ML Kit / Play services QR scanner              ├─ RiskRepository
  └─ Settings and profile stores                    │
                                                     └─ Retrofit / HTTPS
                                                          ↓
                                              FastAPI risk API and history
```

The Android module is organized by responsibility:

- ui/: Compose navigation, onboarding, manual checks, QR scanning, results, history, account, and settings.
- ui/CheckViewModel.kt: asynchronous state for manual risk checks.
- data/RiskRepository.kt: API calls and response handling; RiskGuardApi.kt defines Retrofit endpoints and ApiModels.kt the request/response DTOs.
- data/BackendUrlStore.kt, ApiTokenStore.kt, and LocalProfileStore.kt: local configuration, credentials, and profile setup.
- notifications/FraudNotificationListener.kt: notification text filtering, deduplication, API checks, and local warning notifications.
- notifications/NotificationMonitorPreferences.kt: monitoring switches and last background API status.

## Notification monitoring and privacy

During first-run setup the app checks whether supported messaging clients are installed, explains notification access, and asks the user to enable Android Notification Access. Android presents the actual system permission screen; monitoring also has per-source controls in Settings. SMS/Messages, WhatsApp, and Telegram are supported sources. Signal and other apps can be included through the “Other apps” setting, which is enabled by default.

When enabled, the listener reads text exposed in posted notifications. It ignores ordinary notifications unless text matches payment terms or a bank/wallet mention combined with an account-security action. Repeated identical notification updates are deduplicated briefly. Matching text is sent to the configured Risk Guard API and non-safe results can produce an Android warning notification.

Notification access does not read a messaging app’s full chat history, hidden notification content, or arbitrary message/photo attachments. This client does not inspect images delivered in messaging notifications. To check an image, the user must open the QR scan screen and select an image; QR decoding is performed on-device. The decoded payload, not the image file, is submitted for risk checking. Notification text may include sensitive information, so configure a trusted backend and review its retention and access controls.

## QR scanning and result interpretation

The camera flow uses Google Play services Code Scanner, restricted to QR codes. The image flow uses ML Kit Barcode Scanning locally. The app passes the decoded string to the check flow; it does not treat every QR as a payment QR.

A UPI payload can be parsed for fields such as payee VPA, payee name, amount, currency, and note. A well-formed payload indicates that the data follows expected UPI payment URI structure. It does not prove that the payee owns the VPA or that the QR is safe. Users should verify recipient and amount in their payment app before approving a transfer. Non-UPI QR payloads should be treated as unverified content and checked carefully before opening.

## Backend API

The client uses Retrofit and the configured API base URL. The API implementation is maintained separately from this Android module; response scoring, authentication policy, and history retention are controlled by that service. Common operations include:

| Route | Method | Purpose |
| --- | --- | --- |
| /status | GET | Check API availability and version |
| /check | POST | Score message, link, amount, or recipient inputs |
| /scan-qr | POST | Submit a decoded QR payload or QR image, depending on client/API support |
| /history | GET / DELETE | Fetch or delete the authenticated account’s checks |

Use only an API endpoint you trust. The emulator development default is http://10.0.2.2:8000/; this address is for the Android emulator to reach the host machine. Use HTTPS for a physical device or deployed service. API tokens should be unique to each user and managed by the backend operator. Do not commit production credentials or private datasets to this repository.

## Security notes

- The notification listener is an Android system-level special access granted by the user in system Settings.
- The app excludes its own notifications, filters candidate text locally, and limits notification text before sending it for a check.
- Scanned QR image files are decoded locally; decoded content is what enters the risk-check flow.
- Profile and API-token storage implementations are in app/src/main/java/com/upifraudguard/app/data/. Check those implementations and Android platform behavior before making claims about hardware-backed encryption or at-rest encryption; this README avoids assuming guarantees beyond the code.
- Risk verdicts are decision support. They cannot establish that a payment request is genuine or replace verification in the payment app.

## Build and run

Requirements: Android Studio with Android Gradle Plugin, JDK 17, Android SDK 34, and an Android 8.0/API 26 or newer device or emulator.

1. Start the separately maintained FastAPI service and configure its URL and, if required, an API token in app Settings.
2. Build with the Gradle wrapper:
   ```bash
   ./gradlew assembleDebug
   ```
3. Install on a connected device:
   ```bash
   ./gradlew installDebug
   ```

For local emulator development, the app’s default API URL is http://10.0.2.2:8000/. A physical device needs a reachable HTTPS endpoint. QR camera scanning relies on Google Play services; the gallery image flow uses the ML Kit barcode scanner dependency.
