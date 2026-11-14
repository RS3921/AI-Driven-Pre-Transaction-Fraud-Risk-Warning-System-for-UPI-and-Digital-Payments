# Security Review & Posture Assessment — UPI Fraud Guard

**Date:** 2026-11-10  
**Application:** `upi-fraud-guard-v3`

---

## 1. Authentication & Role-Based Access Control (RBAC)

- **Token Management**:
  - Out-of-band Bearer token authentication configured via `UPI_FRAUD_GUARD_API_USERS` environment variable (`username:token:role`).
  - Passwords/tokens hashed with SHA-256 and verified using constant-time comparison (`hmac.compare_digest`).
  - Fallback role mapping: Unauthenticated requests or unknown roles are rejected or assigned read-only visibility where permitted.
- **Backend Authorization Gates**:
  - Super-admin: Model deployment, rollback, approval, and indicator quarantine.
  - Fraud Analyst / Super-admin: Manual collection triggers, indicator review, and candidate training.
  - Public / Unauthenticated: Health check (`/status`).

## 2. Server-Side Request Forgery (SSRF) Defenses

- **Strict URL Scheme**: Only `http://` and `https://` schemes allowed; fragments and credentials in URLs are rejected.
- **DNS Pinning**: Hostnames are resolved upfront; IPv4/IPv6 addresses are checked for `is_global`. Private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), multicast, and cloud metadata (`metadata.google.internal`, `169.254.169.254`) addresses are blocked.
- **Direct Socket Connection**: HTTP connections are made directly to the validated IP sockaddr via custom `_PinnedHTTPConnection` / `_PinnedHTTPSConnection`, preventing DNS-rebinding / TOCTOU attacks.
- **Redirect Security**: Redirect destinations are fully re-validated against allowlists. Sensitive headers (`Authorization`, API keys) are stripped when redirecting to a different domain.
- **Streaming Resource Limits**: Responses are streamed in 64 KiB chunks with a maximum cap of 5 MiB (`MAX_RESPONSE_BYTES`). Oversized payloads raise `PayloadTooLargeError` without buffering into memory.

## 3. Frontend & DOM-Based XSS Prevention

- **DOM Rendering**: All untrusted backend fields (indicator values, descriptions, source names, case notes, model tags) are escaped with `escapeHtml()` prior to insertion in `innerHTML`.
- **Session Management**: Session tokens are stored in `sessionStorage` and transmitted via standard `Authorization: Bearer <token>` headers via `apiFetch()`.

## 4. Threat Intelligence Integrity & Falsehood Prevention

- **Elimination of Mock/Demo IOC Fallbacks**: Connectors fail closed on upstream network/parsing errors, recording explicit failure logs instead of inserting synthetic threats.
- **Quarantine Workflow**: Historical sample/test IOCs can be quarantined via `/api/intelligence/indicators/{id}/quarantine`, immediately removing them from matching evaluations.

## 5. Remaining Risks & Operational Recommendations

1. **Production TLS**: In production, ensure valid TLS certificates are supplied (`UPI_FRAUD_GUARD_TLS_CERT`, `UPI_FRAUD_GUARD_TLS_KEY`).
2. **Third-Party Rate Limits**: Free tier limits on AbuseIPDB and AlienVault OTX should be monitored with exponential backoff.
3. **Database Concurrency**: The SQLite backend is optimized with WAL mode and short transactions; high-scale multi-worker deployments should transition to PostgreSQL when write throughput exceeds 500 checks/sec.
