"""
Docstring for SGCI.authentification.backend.app.tokens
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import base64
import hashlib
import hmac
import json

from .settings import settings


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _sign(data: bytes) -> str:
    return _b64url_encode(
        hmac.new(settings.JWT_SECRET.encode("utf-8"), data, hashlib.sha256).digest()
    )


def _encode(payload: dict[str, object]) -> str:
    header = {"alg": settings.JWT_ALG, "typ": "JWT"}
    header_json = json.dumps(header, separators=(",", ":"), sort_keys=True)
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    header_b64 = _b64url_encode(header_json.encode("utf-8"))
    payload_b64 = _b64url_encode(payload_json.encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = _sign(signing_input)
    return f"{header_b64}.{payload_b64}.{signature}"


def _ensure_alg() -> None:
    if settings.JWT_ALG != "HS256":
        raise ValueError("Only HS256 is supported")


def create_access_token(sub: str) -> str:
    _ensure_alg()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": sub,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int(
            (now + timedelta(minutes=settings.ACCESS_TOKEN_MINUTES)).timestamp()
        ),
    }
    return _encode(payload)


def create_refresh_token(sub: str) -> tuple[str, datetime]:
    _ensure_alg()
    now = datetime.now(timezone.utc)
    exp = now + timedelta(days=settings.REFRESH_TOKEN_DAYS)
    payload = {
        "sub": sub,
        "type": "refresh",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    return _encode(payload), exp
