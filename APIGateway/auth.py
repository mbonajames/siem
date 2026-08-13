from __future__ import annotations

import base64
import hashlib
import logging
import os
import threading
import xml.etree.ElementTree as ET
from functools import lru_cache
from typing import Any

import httpx
import jwt as pyjwt
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv

log = logging.getLogger(__name__)

load_dotenv()
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

TENANT_ID = os.getenv("AZURE_TENANT_ID", "27439031-8cd6-49af-b8b4-6f97e6cdf6d3")
CLIENT_ID = os.getenv("AZURE_CLIENT_ID",  "d989e502-4133-484d-8de2-c36d9a70c8df")

AUDIENCES = [
    os.getenv("AZURE_API_AUDIENCE", f"api://{CLIENT_ID}"),
    CLIENT_ID,
]

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
ISSUER    = f"{AUTHORITY}/v2.0"

_bearer = HTTPBearer(auto_error=False)

# In-process kid → public key cache; populated on first request, never expires
# (Azure AD rotates SAML certificates infrequently; restart clears cache if needed)
_key_cache: dict[str, Any] = {}


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@lru_cache(maxsize=1)
def _fetch_fed_metadata() -> list[tuple[str, Any]]:
    """
    Fetch the app-specific WS-Federation metadata XML once and return
    (kid, public_key) pairs.  The kid is base64url(SHA-1(cert DER)).
    Azure AD signs OIDC tokens from SAML-configured apps with this certificate.
    """
    url = (
        f"{AUTHORITY}/federationmetadata/2007-06/federationmetadata.xml"
        f"?appid={CLIENT_ID}"
    )
    resp = httpx.get(url, timeout=10)
    resp.raise_for_status()
    root = ET.fromstring(resp.text)

    pairs: list[tuple[str, Any]] = []
    for cert_elem in root.iter("{http://www.w3.org/2000/09/xmldsig#}X509Certificate"):
        try:
            der  = base64.b64decode(cert_elem.text.strip())
            cert = x509.load_der_x509_certificate(der, default_backend())
            kid  = _b64url_encode(hashlib.sha1(der).digest())
            pairs.append((kid, cert.public_key()))
        except Exception:
            continue
    return pairs


def _get_signing_key(token: str) -> Any:
    header = pyjwt.get_unverified_header(token)
    kid    = header.get("kid") or header.get("x5t", "")

    if kid in _key_cache:
        return _key_cache[kid]

    # Populate cache from federation metadata (fetched once, then lru_cache'd)
    for attempt in range(2):
        if attempt == 1:                  # stale cache — force re-fetch
            _fetch_fed_metadata.cache_clear()
        for cert_kid, pub_key in _fetch_fed_metadata():
            _key_cache[cert_kid] = pub_key

        if kid in _key_cache:
            return _key_cache[kid]

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=f"Cannot find signing key: {kid!r}",
        headers={"WWW-Authenticate": "Bearer"},
    )


def decode_token(token: str) -> dict[str, Any]:
    try:
        key = _get_signing_key(token)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        )

    last_error: Exception | None = None
    for aud in AUDIENCES:
        try:
            return pyjwt.decode(
                token,
                key,
                algorithms=["RS256"],
                audience=aud,
                issuer=ISSUER,
            )
        except Exception as exc:
            last_error = exc

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=f"Invalid token: {last_error}",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> dict[str, Any]:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return decode_token(credentials.credentials)


def require_role(*roles: str):
    """Returns a FastAPI dependency that enforces one of the given App Roles."""
    def _guard(claims: dict = Depends(get_current_user)) -> dict:
        user_roles: list[str] = claims.get("roles", [])
        if not any(r in user_roles for r in roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required role: {', '.join(roles)}",
            )
        return claims
    return _guard


def _warm_cache() -> None:
    try:
        for cert_kid, pub_key in _fetch_fed_metadata():
            _key_cache[cert_kid] = pub_key
        log.info("Auth key cache warmed — %d key(s) loaded", len(_key_cache))
    except Exception as exc:
        log.warning("Auth cache warm-up failed (will retry on first request): %s", exc)


threading.Thread(target=_warm_cache, daemon=True).start()
