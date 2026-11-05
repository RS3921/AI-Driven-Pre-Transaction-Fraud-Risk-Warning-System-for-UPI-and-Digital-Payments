"""Bearer-token authentication for provisioned UPI Fraud Guard users.

Set UPI_FRAUD_GUARD_API_USERS to a JSON object mapping user IDs to long,
random API tokens. Tokens are hashed before comparison and are never logged.
With no users configured, only the local-development identity is available;
run_api.py prevents that mode from binding to a network interface.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os

from fastapi import Header, HTTPException


def _user_token_hashes() -> dict[str, str]:
    raw = os.environ.get("UPI_FRAUD_GUARD_API_USERS", "").strip()
    if not raw:
        return {}
    try:
        users = json.loads(raw)
    except json.JSONDecodeError as error:
        raise RuntimeError("UPI_FRAUD_GUARD_API_USERS must contain a JSON object of user IDs and tokens") from error
    if not isinstance(users, dict) or not users:
        raise RuntimeError("UPI_FRAUD_GUARD_API_USERS must contain a non-empty JSON object")
    result = {}
    for user_id, token in users.items():
        if not isinstance(user_id, str) or not user_id.strip() or len(user_id) > 100:
            raise RuntimeError("API user IDs must be non-empty strings of at most 100 characters")
        if not isinstance(token, str) or len(token) < 32:
            raise RuntimeError("Each API token must be a random string of at least 32 characters")
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        if digest in result:
            raise RuntimeError("API tokens must be unique")
        result[digest] = user_id
    return result


def authentication_required() -> bool:
    return os.environ.get("UPI_FRAUD_GUARD_REQUIRE_AUTH", "").strip().lower() in {"1", "true", "yes", "on"} or bool(_user_token_hashes())


def validate_security_configuration() -> None:
    required = os.environ.get("UPI_FRAUD_GUARD_REQUIRE_AUTH", "").strip().lower() in {"1", "true", "yes", "on"}
    users = _user_token_hashes()
    if required and not users:
        raise RuntimeError("Authentication is required but UPI_FRAUD_GUARD_API_USERS has no configured users")


def current_user_id(authorization: str | None = Header(default=None)) -> str:
    token_hashes = _user_token_hashes()
    required = authentication_required()
    if not required and not token_hashes:
        return "local-development"
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() == "bearer" and token:
        supplied_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        for known_hash, user_id in token_hashes.items():
            if hmac.compare_digest(supplied_hash, known_hash):
                return user_id
        raise HTTPException(status_code=401, detail="Invalid API token", headers={"WWW-Authenticate": "Bearer"})
    if required:
        raise HTTPException(status_code=401, detail="A valid API token is required", headers={"WWW-Authenticate": "Bearer"})
    return "local-development"
