"""
Bearer-token authentication and Role-Based Access Control (RBAC) for UPI Fraud Guard.

Supported RBAC Roles:
1. super_admin: Full system access, config, user management, history deletion.
2. fraud_analyst: Risk assessment, threat intelligence, mule detection, case investigation.
3. investigation_officer: Case investigation, note updates, resolution tracking.
4. read_only_auditor: Analytics, model performance view, audit logs.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import List, Callable
from fastapi import Header, HTTPException, Depends

VALID_ROLES = {"super_admin", "fraud_analyst", "investigation_officer", "read_only_auditor"}

# Default role mapping for local development identity
USER_ROLES: dict[str, str] = {
    "local-development": "super_admin",
    "admin": "super_admin",
    "analyst": "fraud_analyst",
    "investigator": "investigation_officer",
    "auditor": "read_only_auditor",
}


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


def current_user_role(user_id: str = Depends(current_user_id)) -> str:
    """Resolves the user's role from configuration or defaults to super_admin for local dev."""
    return USER_ROLES.get(user_id, "fraud_analyst")


def require_role(allowed_roles: List[str]) -> Callable:
    """FastAPI Dependency for Enforcing Role-Based Access Control (RBAC)."""
    def role_checker(role: str = Depends(current_user_role)) -> str:
        if role not in allowed_roles and role != "super_admin":
            raise HTTPException(
                status_code=403,
                detail=f"Access denied: Role '{role}' does not have permission for this operation. Required: {allowed_roles}",
            )
        return role

    return role_checker
