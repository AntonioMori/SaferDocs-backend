"""Cifragem autenticada com AES-256-GCM (REQ-12 e REQ-45).

Cada uso tem a própria chave, derivada da MASTER_KEY por HKDF-SHA256 com um
contexto diferente. Assim, a chave que cifra segredos do TOTP nunca é a
mesma que cifra as chaves privadas de assinatura.

Formato do texto cifrado: nonce (12 bytes) || ciphertext || tag (16 bytes).
"""

import base64
import os
from enum import StrEnum
from functools import lru_cache

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.config import get_settings

NONCE_SIZE = 12


class AeadContext(StrEnum):
    TOTP_SECRET = "saferdocs/totp-secret/v1"
    SIGNING_KEY = "saferdocs/signing-key/v1"


class DecryptionError(Exception):
    """Texto cifrado adulterado, truncado ou de outro contexto."""


@lru_cache
def _cipher(context: AeadContext) -> AESGCM:
    master = base64.b64decode(get_settings().master_key.get_secret_value())
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=context.value.encode()).derive(master)
    return AESGCM(key)


def encrypt(context: AeadContext, plaintext: bytes, associated_data: bytes | None = None) -> bytes:
    """Cifra `plaintext`. `associated_data` (ex.: o id do usuário) amarra o dado ao dono."""
    nonce = os.urandom(NONCE_SIZE)
    return nonce + _cipher(context).encrypt(nonce, plaintext, associated_data)


def decrypt(context: AeadContext, data: bytes, associated_data: bytes | None = None) -> bytes:
    if len(data) < NONCE_SIZE + 16:
        raise DecryptionError("texto cifrado inválido")
    try:
        return _cipher(context).decrypt(data[:NONCE_SIZE], data[NONCE_SIZE:], associated_data)
    except InvalidTag:
        raise DecryptionError("texto cifrado inválido") from None
