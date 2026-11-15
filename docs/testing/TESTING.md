# AUTOMATED TESTING & QUALITY ASSURANCE

---

## Running the Automated Test Suite

To run the complete automated test suite:

```bash
cd upi-fraud-guard-v3
python test_suite.py
```

---

## Test Coverage Matrix

1. **`test_01_health_and_status`**: Verifies `/status` health response and version string (`2.6.0-Enterprise`).
2. **`test_02_dual_feed_status`**: Verifies Threat Intelligence and Transaction Feed health.
3. **`test_03_pre_transaction_check_safe`**: Verifies safe transaction check workflow.
4. **`test_04_pre_transaction_check_threat_vpa`**: Verifies threat VPA correlation and automatic case creation.
5. **`test_05_mule_analysis`**: Verifies NetworkX graph mule account candidate detection.
6. **`test_06_investigations_workflow`**: Verifies case queue listing and status updates.
7. **`test_07_model_monitoring`**: Verifies model performance and statistical population drift calculation.
