# ENTERPRISE SECURITY SPECIFICATION

---

## 1. Authentication & Role-Based Access Control (RBAC)

UPI Fraud Guard implements a 4-tier Role-Based Access Control (RBAC) framework:

1. **`super_admin`**: Full system access, security configuration, user management, history deletion, model retraining approvals.
2. **`fraud_analyst`**: Risk assessment, threat intelligence management, mule account detection, case investigation.
3. **`investigation_officer`**: Case investigation, note updates, case resolution tracking.
4. **`read_only_auditor`**: Analytics view, model metrics, audit log inspection.

---

## 2. On-Device Security & Cryptography

* **Android Keystore System**: Key pairs and secret keys are stored hardware-backed (`AndroidKeyStore`).
* **AES-256-GCM Encryption**: Local 2FA secrets and per-user API tokens are encrypted with AES-256-GCM before persistent storage.
* **RFC 6238 2FA Authenticator Engine**: Generates 6-digit TOTP codes refreshing every 30 seconds using SHA-1 HMAC.
* **Network Security Policy**: Cleartext HTTP is restricted strictly to local emulator loopback (`10.0.2.2`). TLS is enforced for all remote destinations.

---

## 3. Privacy & Audit Retention

* **30-Day Automated Retention**: Audit records in the SQLite database are automatically purged after 30 days.
* **Notification Filter Privacy**: The background Notification Listener screens incoming alerts using regex pre-filters. Personal chats, generic messages, and standalone OTPs are ignored on the device and never transmitted.
