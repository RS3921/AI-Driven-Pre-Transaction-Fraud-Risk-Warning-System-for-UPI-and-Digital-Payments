# ENTERPRISE API DOCUMENTATION

**Base URL**: `http://127.0.0.1:8000/`  
**Interactive Swagger Docs**: `http://127.0.0.1:8000/api-docs`  

---

## Endpoint Specifications

### 1. System Status
* **Endpoint**: `GET /status`
* **Response**:
```json
{
  "status": "running",
  "version": "2.6.0-Enterprise",
  "authentication_required": false,
  "modules": ["message", "url_qr", "transaction", "dual_feed", "mule_detection", "investigations"]
}
```

### 2. Pre-Transaction Risk Assessment
* **Endpoint**: `POST /check`
* **Headers**: `Authorization: Bearer <token>`
* **Request Body**:
```json
{
  "message": "Urgent electricity disconnection. Pay immediately.",
  "url_or_qr": "upi://pay?pa=scammer@upi&pn=Support",
  "amount": 15000.0,
  "recipient": "scammer@upi",
  "payments_last_hour": 6,
  "is_new_recipient": true
}
```
* **Response**:
```json
{
  "verdict": "High Risk",
  "risk_score": 0.94,
  "reasons": [
    "Urgent payment action detected",
    "Recipient VPA 'scammer@upi' is listed in Threat Intelligence feed",
    "High transaction velocity (6 payments in last hour)"
  ],
  "investigation_case_id": "CASE-20260301-1002"
}
```

### 3. Dual-Feed Intelligence Status
* **Endpoint**: `GET /feed-status`
* **Response**:
```json
{
  "threat_feed": {
    "name": "Threat Intelligence Feed",
    "healthy": true,
    "vpa_threats_count": 9,
    "phishing_urls_count": 6556
  },
  "transaction_feed": {
    "name": "Transaction Intelligence Feed",
    "healthy": true
  }
}
```

### 4. Mule Account Graph Analysis
* **Endpoint**: `GET /mule-analysis`
* **Response**:
```json
{
  "total_nodes": 10,
  "total_edges": 9,
  "suspicious_mule_count": 4,
  "mule_candidates": [
    {
      "vpa": "mule_target@ybl",
      "is_mule_candidate": true,
      "mule_risk_score": 0.55,
      "in_degree": 5,
      "out_degree": 1
    }
  ]
}
```

### 5. Fraud Investigation Queue
* **Endpoint**: `GET /investigations`
* **Query Params**: `status` (optional), `priority` (optional), `limit` (default: 50)
* **Response**: Array of investigation case records.

### 6. Case Update
* **Endpoint**: `POST /investigations/{case_id}/update`
* **Request Body**:
```json
{
  "status": "Under Investigation",
  "assigned_to": "analyst_alex",
  "add_note": "Verified VPA against threat feed"
}
```

### 7. Model Monitoring & Data Drift
* **Endpoint**: `GET /model-monitoring`
* **Response**: Statistical population drift analysis & model precision/recall metrics.
