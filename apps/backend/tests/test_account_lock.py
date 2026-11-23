"""REQ-03: bloqueio temporário da conta após falhas consecutivas."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.db.session import get_sessionmaker
from app.main import app
from app.services.auth_service import find_user_by_email

SENHA = "Senha-Forte#2026"
N = get_settings().login_max_attempts


@pytest.fixture
def client(migrated_db):
    return TestClient(app)


@pytest.fixture
def email(client):
    email = f"lock-{uuid.uuid4().hex[:10]}@teste.dev"
    assert (
        client.post(
            "/api/v1/auth/register", json={"name": "Ana", "email": email, "password": SENHA}
        ).status_code
        == 201
    )
    return email


def _login(client, email, senha=SENHA):
    return client.post("/api/v1/auth/login", json={"email": email, "password": senha})


def _usuario(email):
    with get_sessionmaker()() as db:
        return find_user_by_email(db, email)


def test_n_falhas_bloqueiam_e_nem_a_senha_certa_entra(client, email):
    for _ in range(N):
        assert _login(client, email, "errada").status_code == 401
    user = _usuario(email)
    minutos = get_settings().login_lock_minutes
    assert user.locked_until is not None
    restante = user.locked_until - datetime.now(UTC)
    assert timedelta(minutes=minutos - 1) < restante <= timedelta(minutes=minutos)

    resposta = _login(client, email)
    assert resposta.status_code == 401
    assert resposta.json()["code"] == "AUTH_001"


def test_resposta_de_conta_bloqueada_e_igual_a_senha_errada(client, email):
    errada = _login(client, email, "errada").json()
    for _ in range(N - 1):
        _login(client, email, "errada")
    bloqueada = _login(client, email).json()
    assert {k: errada[k] for k in ("code", "message")} == {k: bloqueada[k] for k in ("code", "message")}


def test_apos_o_bloqueio_expirar_a_senha_certa_entra_e_zera_o_contador(client, email):
    for _ in range(N):
        _login(client, email, "errada")
    with get_sessionmaker()() as db:
        user = find_user_by_email(db, email)
        user.locked_until = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()

    assert _login(client, email).status_code == 200
    user = _usuario(email)
    assert user.locked_until is None
    assert user.failed_login_count == 0


def test_sucesso_zera_falhas_anteriores(client, email):
    for _ in range(N - 1):
        _login(client, email, "errada")
    assert _login(client, email).status_code == 200
    assert _usuario(email).failed_login_count == 0
    for _ in range(N - 1):
        _login(client, email, "errada")
    assert _usuario(email).locked_until is None  # contador recomeçou do zero
