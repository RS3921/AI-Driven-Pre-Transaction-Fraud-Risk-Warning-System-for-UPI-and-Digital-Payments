"""
Run this to start the API server.

Just run:   python run_api.py

Then open http://localhost:8000 in your browser.
Press CTRL+C in this terminal to stop the server.
"""

import os
import ipaddress
import uvicorn
from api.security import authentication_required, validate_security_configuration

if __name__ == "__main__":
    host = os.environ.get("UPI_FRAUD_GUARD_HOST", "127.0.0.1")
    port = int(os.environ.get("UPI_FRAUD_GUARD_PORT", "8000"))
    validate_security_configuration()
    try:
        is_loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        is_loopback = host.lower() == "localhost"

    certfile = os.environ.get("UPI_FRAUD_GUARD_TLS_CERT", "").strip()
    keyfile = os.environ.get("UPI_FRAUD_GUARD_TLS_KEY", "").strip()
    if not is_loopback:
        if not authentication_required():
            raise SystemExit("Refusing network binding without API users. Configure UPI_FRAUD_GUARD_API_USERS first.")
        if not certfile or not keyfile:
            raise SystemExit("Refusing network binding without HTTPS. Set UPI_FRAUD_GUARD_TLS_CERT and UPI_FRAUD_GUARD_TLS_KEY.")
    if bool(certfile) != bool(keyfile):
        raise SystemExit("Set both UPI_FRAUD_GUARD_TLS_CERT and UPI_FRAUD_GUARD_TLS_KEY, or neither.")

    scheme = "https" if certfile else "http"
    print(f"Starting {scheme.upper()} API on {host}:{port}. The browser dashboard is optional.\n")
    uvicorn.run(
        "api.main:app", host=host, port=port, reload=False, app_dir=".",
        ssl_certfile=certfile or None, ssl_keyfile=keyfile or None,
    )
