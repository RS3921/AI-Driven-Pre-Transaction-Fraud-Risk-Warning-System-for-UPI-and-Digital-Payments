# Git Branching Strategy & Workflow Specification
**UPI Fraud Guard Enterprise v2.6.0-RC1**

**Document Version:** 1.0.0  
**Target Repository:** [`https://github.com/RS3921/AI-Driven-Pre-Transaction-Fraud-Risk-Warning-System-for-UPI-and-Digital-Payments.git`](https://github.com/RS3921/AI-Driven-Pre-Transaction-Fraud-Risk-Warning-System-for-UPI-and-Digital-Payments.git)

---

## 1. Overview & Branching Structure

This document defines the Git branching model for **UPI Fraud Guard Enterprise**. The strategy maintains a stable, release-ready `main` production baseline while enabling parallel feature development and bug fixes through dedicated, isolated branches.

```text
  main (Production & Release Candidates)
   │
   └──► development (Integration & Verification Baseline)
         ├──► feature/continuous-intelligence
         ├──► feature/payment-link-analysis
         └──► bugfix/security
```

---

## 2. Branch Hierarchy & Purpose

| Branch Name | Purpose & Scope | Parent Branch | Deployment / Release Target |
| :--- | :--- | :---: | :---: |
| **`main`** | Stable, release-ready production baseline. All code on `main` must pass full regression testing and security audits. | N/A | Production & Release Candidates (`vX.Y.Z`) |
| **`development`** | Central integration and verification baseline for ongoing development. Feature branches merge here for continuous integration. | `main` | Staging / Pilot Testing Environments |
| **`feature/continuous-intelligence`** | Dedicated feature branch for developing and maintaining CTI connectors, threat feed collectors, and ML governance pipelines. | `development` | Merges into `development` |
| **`feature/payment-link-analysis`** | Dedicated feature branch for AUIE URL type classification, multi-hop redirect analysis, and static content inspection. | `development` | Merges into `development` |
| **`bugfix/security`** | Dedicated branch for hotfixes addressing security vulnerabilities, SSRF protection, RBAC policies, or dependency patches. | `development` | Merges into `development` |

---

## 3. Workflow Specifications

### A. Developing New Features (`feature/*`)
1. **Branch Creation:** Always branch out from the latest verified `development` branch:
   ```bash
   git checkout development
   git pull origin development
   git checkout -b feature/<feature-name>
   ```
2. **Development & Unit Testing:** Implement feature changes and create dedicated test suites.
3. **Merging to `development`:** Once all unit tests pass, submit a Pull Request (PR) to merge `feature/<feature-name>` into `development`. Never merge directly to `main`.

### B. Security Fixes & Hotfixes (`bugfix/*`)
1. **Branch Creation:** Branch out from `development` (or `main` for critical production hotfixes):
   ```bash
   git checkout -b bugfix/security development
   ```
2. **Verification & Audit:** Verify fix against security regression test suite (`test_auie_security_hardening.py`).
3. **Merge & Promotion:** Merge to `development`, re-verify, and promote to `main` upon approval.

### C. Promoting `development` to `main` (Release Promotion)
1. **Regression Gate:** Execute the complete test suite across all 12 test modules:
   ```bash
   python -m unittest test_payment_link_enhancement.py test_auie_security_hardening.py test_auie_expanded_benchmark.py test_auie.py test_continuous_intelligence_learning.py test_lightweight_continuous_intelligence.py test_critical_remediations.py test_cti_phase2.py test_cti_phase3.py test_cti_phase4.py test_cti_phase5.py test_cti_phase6.py test_suite.py
   ```
2. **PR Approval & Fast-Forward Merge:** Merge `development` into `main` only after 100% test pass rate.
3. **Release Tagging:** Tag stable release milestones on `main`:
   ```bash
   git checkout main
   git tag -a v2.6.0-RC1 -m "Release Candidate v2.6.0-RC1 with AUIE and CTI Continuous Intelligence"
   git push origin v2.6.0-RC1
   ```

---

## 4. Git Safety Rules

- **Zero Force-Push Policy:** `git push --force` or `git push --delete` on `main` or `development` is strictly prohibited.
- **Linear History Preservation:** Do not rewrite, rebase, or reset public commit history.
- **Secrets & Credentials Prevention:** `.env` files, SQLite database binaries (`*.db`), private TLS keys (`*.pem`, `*.key`), and IDE settings are excluded via `.gitignore`.
