"""Configuração comum dos testes.

Define um ambiente de teste completo antes de a aplicação ser importada,
com chaves geradas na hora (nada de segredo fixo no repositório).

Testes que usam o banco precisam do PostgreSQL descartável:
    docker compose --profile test up -d db-test
(ou defina TEST_DATABASE_URL apontando para outro banco de teste).
"""

import base64
import os
import secrets

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy.exc import OperationalError


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
        "TEST_DATABASE_URL",
        "postgresql+psycopg://saferdocs:saferdocs_test@127.0.0.1:55433/saferdocs_test",
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


def alembic_config():
    from pathlib import Path

    from alembic.config import Config

    root = Path(__file__).resolve().parent.parent
    config = Config(str(root / "alembic.ini"))
    config.set_main_option("script_location", str(root / "alembic"))
    return config


def session_token(user_id, *, user_agent: str = "testclient", ip: str = "testclient") -> str:
    """Cria uma sessão real no banco e devolve um access token dela.

    Os valores padrão batem com o que o TestClient envia (IP e User-Agent
    "testclient"), para o token passar nas verificações da Figura 4.
    """
    from app.crypto.jwt import encode_access_token
    from app.crypto.keyed_hash import keyed_hash
    from app.db.models import UserSession
    from app.db.session import get_sessionmaker

    with get_sessionmaker()() as db:
        session = UserSession(
            user_id=user_id, user_agent=user_agent, ip_hmac=keyed_hash(ip), ua_hmac=keyed_hash(user_agent)
        )
        db.add(session)
        db.commit()
        token, _ = encode_access_token(user_id, {"session_id": str(session.id), "ua_hash": session.ua_hmac})
    return token


@pytest.fixture(scope="session")
def migrated_db(database_available) -> None:
    """Banco de teste com todas as migrations aplicadas (RNF-09)."""
    from alembic import command

    command.upgrade(alembic_config(), "head")


@pytest.fixture(scope="session")
def database_available() -> None:
    """Falha com instrução clara se o banco de teste não estiver no ar."""
    from app.db.session import check_database

    try:
        check_database()
    except OperationalError:
        pytest.fail(
            "Banco de teste indisponível. Suba com: docker compose --profile test up -d db-test",
            pytrace=False,
        )
