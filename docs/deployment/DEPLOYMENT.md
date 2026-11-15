# DEPLOYMENT GUIDE

---

## Local Development Deployment

```bash
# Start Python API
cd upi-fraud-guard-v3
python run_api.py
```

## Production Docker Container Deployment

```bash
# Build & start container
docker-compose up --build -d

# Verify logs
docker logs -f upi_fraud_guard_api
```

## Production Environment Variables

| Variable | Description | Default |
| :--- | :--- | :--- |
| `UPI_FRAUD_GUARD_HOST` | Server host binding | `127.0.0.1` |
| `UPI_FRAUD_GUARD_PORT` | Server port | `8000` |
| `UPI_FRAUD_GUARD_REQUIRE_AUTH` | Enforce API token auth | `false` |
| `UPI_FRAUD_GUARD_API_USERS` | JSON mapping user IDs to API tokens | `{}` |
| `UPI_FRAUD_GUARD_TLS_CERT` | Path to TLS HTTPS Certificate | `""` |
| `UPI_FRAUD_GUARD_TLS_KEY` | Path to TLS HTTPS Private Key | `""` |
