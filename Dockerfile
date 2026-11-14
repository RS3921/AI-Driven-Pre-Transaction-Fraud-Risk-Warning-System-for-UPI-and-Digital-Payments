# Enterprise Dockerfile for UPI Fraud Guard API
FROM python:3.13-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libzbar0 \
    && rm -rf /var/lib/apt/lists/*

# Copy python dependencies
COPY upi-fraud-guard-v3/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir networkx

# Copy application code
COPY upi-fraud-guard-v3 /app

EXPOSE 8000

ENV UPI_FRAUD_GUARD_HOST=0.0.0.0
ENV UPI_FRAUD_GUARD_PORT=8000

CMD ["python", "run_api.py"]
