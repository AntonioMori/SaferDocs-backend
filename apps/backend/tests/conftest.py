"""Configuração comum dos testes.

Define um ambiente de teste completo antes de a aplicação ser importada,
com chaves geradas na hora (nada de segredo fixo no repositório).
"""

import base64
import os
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _es256_pair() -> tuple[str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    private = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return _b64(private), _b64(public)


_private, _public = _es256_pair()

TEST_ENV = {
    "APP_ENV": "test",
    "DATABASE_URL": os.environ.get(
        "TEST_DATABASE_URL", "postgresql+psycopg://saferdocs:saferdocs@localhost:5432/saferdocs_test"
    ),
    "JWT_PRIVATE_KEY_PEM_B64": _private,
    "JWT_PUBLIC_KEY_PEM_B64": _public,
    "MASTER_KEY": _b64(secrets.token_bytes(32)),
    "HASH_PEPPER": _b64(secrets.token_bytes(32)),
    "CORS_ALLOWED_ORIGINS": "http://localhost:3039",
    "WEBAUTHN_RP_ID": "localhost",
    "WEBAUTHN_ORIGIN": "http://localhost:3039",
}

for _name, _value in TEST_ENV.items():
    os.environ[_name] = _value
