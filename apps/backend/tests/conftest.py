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
    # Fixo aqui para um .env local com outro valor não mudar o resultado dos testes.
    "CORS_MAX_AGE_SECONDS": "600",
    # Limites altos: os testes de login fazem muitas tentativas seguidas e medem o
    # bloqueio da conta (REQ-03). Os testes do rate limit (REQ-05) fixam os próprios.
    "RATE_LIMIT_LOGIN_PER_IP": "1000/minute",
    "RATE_LIMIT_LOGIN_PER_ACCOUNT": "1000/minute",
    "RATE_LIMIT_VERIFY_PER_IP": "1000/minute",
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
        token, _ = encode_access_token(
            user_id, {"session_id": str(session.id), "ua_hash": session.ua_hmac, "ip": session.ip_hmac}
        )
    return token


@pytest.fixture(autouse=True)
def _zera_rate_limit():
    """Cada teste começa com os contadores do rate limit zerados."""
    try:
        from app.middlewares.rate_limit import reset_rate_limits
    except ModuleNotFoundError:
        # worker-tests (container do pdf-worker) não tem as dependências da API.
        yield
        return

    reset_rate_limits()
    yield
    reset_rate_limits()


def make_signer(name: str = "Teste"):
    """Usuário só em memória, com par de chaves de verdade (REQ-45), para testar a assinatura."""
    import uuid as _uuid

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    from app.db.models import User
    from app.services.user_keys import generate_user_keys

    user = User(id=_uuid.uuid4(), name=name, email="teste@teste.dev", password_hash="!")
    generate_user_keys(None, user)  # type: ignore[arg-type]
    pem = x509.load_der_x509_certificate(user.signing_cert).public_bytes(serialization.Encoding.PEM)
    return user, pem


def make_pdf(pages: int = 1, size: tuple[float, float] = (595, 842)) -> bytes:
    """PDF válido de verdade, gerado com o pikepdf (dependência só de teste)."""
    import io

    import pikepdf

    document = pikepdf.new()
    for _ in range(pages):
        document.add_blank_page(page_size=size)
    buffer = io.BytesIO()
    document.save(buffer)
    return buffer.getvalue()


@pytest.fixture
def fake_pdf_worker(monkeypatch):
    """Troca o socket Unix do pdf-worker por um par de sockets em memória.

    Do outro lado roda o código real do worker (`pdf_worker.task.handle`), no
    mesmo processo. Funciona no Windows, que não tem AF_UNIX. O isolamento de
    verdade (container sem rede) é testado no Docker. Devolve a lista de
    pedidos recebidos, para os testes conferirem o que a API mandou.
    """
    import socket
    import threading

    from pdf_worker import task

    pedidos: list[bytes] = []

    def connect(path: str, timeout: float) -> socket.socket:
        api_side, worker_side = socket.socketpair()
        api_side.settimeout(timeout)

        def serve() -> None:
            with worker_side:
                chunks = []
                while chunk := worker_side.recv(1024 * 1024):
                    chunks.append(chunk)
                pedido = b"".join(chunks)
                pedidos.append(pedido)
                worker_side.sendall(task.handle(pedido))

        threading.Thread(target=serve, daemon=True).start()
        return api_side

    monkeypatch.setattr("app.pdf.client._connect", connect)
    return pedidos


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
