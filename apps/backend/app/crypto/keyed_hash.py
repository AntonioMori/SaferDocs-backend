"""HMAC-SHA256 com o HASH_PEPPER.

Usado onde um hash simples seria fácil de reverter por força bruta: IP
(espaço pequeno de valores), User-Agent e códigos de recuperação. Sem o
pepper, que só existe no servidor, o hash não pode ser recalculado.
"""

import base64
import hashlib
import hmac
from functools import lru_cache

from app.core.config import get_settings


@lru_cache
def _pepper() -> bytes:
    return base64.b64decode(get_settings().hash_pepper.get_secret_value())


def keyed_hash(value: str) -> str:
    """HMAC-SHA256(value, HASH_PEPPER) em hexadecimal (64 caracteres)."""
    return hmac.new(_pepper(), value.encode(), hashlib.sha256).hexdigest()


def keyed_hash_matches(value: str, expected_hex: str) -> bool:
    """Compara em tempo constante."""
    return hmac.compare_digest(keyed_hash(value), expected_hex)
