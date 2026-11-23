"""Emissão e validação do access token JWT (ES256).

Claims: iss, sub, iat, exp (REQ-18), jti (REQ-24) e session_id (REQ-28).
As verificações além da assinatura ficam em app/api/deps.py (Figura 4).
"""

import base64
import uuid
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from typing import Any

import jwt

from app.core.config import get_settings

ALGORITHM = "ES256"


@lru_cache
def _keys() -> tuple[bytes, bytes]:
    settings = get_settings()
    private = base64.b64decode(settings.jwt_private_key_pem_b64.get_secret_value())
    public = base64.b64decode(settings.jwt_public_key_pem_b64)
    return private, public


def encode_access_token(subject: uuid.UUID, extra_claims: dict[str, Any] | None = None) -> tuple[str, dict]:
    """Cria um access token assinado. Retorna o token e os claims usados."""
    settings = get_settings()
    now = datetime.now(UTC)
    claims: dict[str, Any] = {
        "iss": settings.jwt_issuer,
        "sub": str(subject),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=settings.access_token_ttl_seconds)).timestamp()),
        "jti": str(uuid.uuid4()),
        **(extra_claims or {}),
    }
    return jwt.encode(claims, _keys()[0], algorithm=ALGORITHM), claims


def decode_access_token(token: str) -> dict[str, Any]:
    """Valida assinatura, algoritmo fixo, emissor e expiração. Lança jwt.PyJWTError."""
    return jwt.decode(
        token,
        _keys()[1],
        algorithms=[ALGORITHM],
        issuer=get_settings().jwt_issuer,
        options={"require": ["exp", "iat", "sub", "jti", "iss", "session_id"]},
    )
