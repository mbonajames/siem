from __future__ import annotations

import os
from functools import lru_cache
from typing import Any

import httpx
from dotenv import load_dotenv

load_dotenv()
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

TENANT_ID = os.getenv("AZURE_TENANT_ID", "27439031-8cd6-49af-b8b4-6f97e6cdf6d3")
CLIENT_ID  = os.getenv("AZURE_CLIENT_ID",  "d989e502-4133-484d-8de2-c36d9a70c8df")
# Must match the Application ID URI shown in App Registration → Expose an API
AUDIENCE   = os.getenv("AZURE_API_AUDIENCE", "api://d989e502-4133-484d-8de2-c36d9a70c8df")
AUTHORITY  = f"https://login.microsoftonline.com/{TENANT_ID}"
JWKS_URI   = f"{AUTHORITY}/discovery/v2.0/keys"
ISSUER     = f"{AUTHORITY}/v2.0"

_bearer = HTTPBearer(auto_error=False)


@lru_cache(maxsize=1)
def _fetch_jwks() -> dict:
    resp = httpx.get(JWKS_URI, timeout=10)
    resp.raise_for_status()
    return resp.json()


def _signing_key(kid: str) -> dict:
    for attempt in range(2):
        if attempt == 1:
            _fetch_jwks.cache_clear()
        for key in _fetch_jwks().get("keys", []):
            if key.get("kid") == kid:
                return key
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown signing key")


def decode_token(token: str) -> dict[str, Any]:
    try:
        header = jwt.get_unverified_header(token)
        key    = _signing_key(header["kid"])
        return jwt.decode(
            token, key,
            algorithms=["RS256"],
            audience=AUDIENCE,
            issuer=ISSUER,
        )
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        )


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> dict[str, Any]:
    if not credentials:
        return {}
    return decode_token(credentials.credentials)


def require_role(*roles: str):
    """Factory: returns a dependency that enforces one of the given App Roles."""
    def _guard(claims: dict = Depends(get_current_user)) -> dict:
        user_roles: list[str] = claims.get("roles", [])
        if not any(r in user_roles for r in roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required role: {', '.join(roles)}",
            )
        return claims
    return _guard
