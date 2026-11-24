"""Segundo fator com TOTP (REQ-11 a 16).

O segredo tem 160 bits (20 bytes do CSPRNG, o tamanho recomendado pela
RFC 4226) e fica no banco cifrado com AES-256-GCM, com chave derivada da
MASTER_KEY só para este uso e o id do usuário como dado associado: o valor
cifrado de uma conta não pode ser copiado para outra (REQ-12).
"""

import base64
import secrets

from app.crypto.aead import AeadContext, decrypt, encrypt
from app.db.models import User

SECRET_BYTES = 20  # 160 bits


def generate_secret() -> str:
    """Segredo novo em base32, o formato que os apps autenticadores leem."""
    return base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode()


def store_secret(user: User, secret_b32: str) -> None:
    user.totp_secret_enc = encrypt(
        AeadContext.TOTP_SECRET, secret_b32.encode(), associated_data=user.id.bytes
    )


def load_secret(user: User) -> str | None:
    if user.totp_secret_enc is None:
        return None
    return decrypt(AeadContext.TOTP_SECRET, user.totp_secret_enc, associated_data=user.id.bytes).decode()
