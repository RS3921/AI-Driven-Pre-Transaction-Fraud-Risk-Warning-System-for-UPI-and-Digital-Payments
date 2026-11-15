# CHANGELOG

## [2.6.0-Enterprise] - March 2026

### Added
- **Dual-Feed Intelligence Architecture (`dual_feed.py`)**: Correlates Transaction Feed velocity signals with Threat Intelligence repositories (6,500+ phishing URLs & threat VPAs).
- **NetworkX Graph-Based Mule Account Detector (`mule_detection.py`)**: Identifies high fan-in accounts, rapid distribution nodes, and circular transaction loops.
- **Fraud Investigation Centre (`investigation.py`)**: Centralized case queue, status lifecycle management (`New`, `Under Investigation`, `Escalated`, `Resolved`, `False Positive`), case assignment, and audit timelines.
- **Model Performance & Data Drift Monitor (`model_monitor.py`)**: Statistical population stability analysis and precision/recall evaluation metrics.
- **4-Role RBAC Security (`api/security.py`)**: Enforces permissions for `super_admin`, `fraud_analyst`, `investigation_officer`, and `read_only_auditor`.
- **5-Tab Enterprise Web Dashboard (`frontend/index.html`, `frontend/script.js`)**: Interactive tabs for Overview, Dual-Feed Threat, Mule Graph, Investigations, and Model Drift.
- **Containerization & CI/CD**: Added `Dockerfile` and `docker-compose.yml`.
- **Comprehensive Documentation Suite**: Added `PROJECT_AUDIT.md`, `ARCHITECTURE.md`, `INSTALLATION.md`, `API_DOCUMENTATION.md`, `SECURITY.md`, `MODEL_DOCUMENTATION.md`, `DEPLOYMENT.md`, `TESTING.md`, `CHANGELOG.md`.
- **Android App Enhancements**: Added 2FA QR Code generator, Compulsory Notification Access setup flow, and fixed Search/Result single-shot state consumption.
