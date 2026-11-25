"""REQ-23: no logout o refresh token também é invalidado."""

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.crypto.jwt import decode_access_token
from app.db.models import RefreshToken, UserSession
from app.db.session import get_sessionmaker
from app.main import app
from app.services.token_service import REFRESH_COOKIE_NAME

SENHA = "Senha-Forte#2026"


@pytest.fixture
def client(migrated_db):
    return TestClient(app, headers={"Origin": "http://localhost:3039"})  # o front manda Origin (REQ-65)


def _entrar(client):
    email = f"out2-{uuid.uuid4().hex[:10]}@teste.dev"
    client.post("/api/v1/auth/register", json={"name": "Ana", "email": email, "password": SENHA})
    resposta = client.post("/api/v1/auth/login", json={"email": email, "password": SENHA})
    token = resposta.json()["access_token"]
    return token, uuid.UUID(decode_access_token(token)["session_id"])


def _sair(client, token):
    return client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})


def test_logout_invalida_o_refresh_e_encerra_a_sessao(client):
    token, session_id = _entrar(client)
    assert _sair(client, token).status_code == 204
    with get_sessionmaker()() as db:
        sessao = db.get(UserSession, session_id)
        refresh = db.scalars(select(RefreshToken).where(RefreshToken.session_id == session_id)).all()
    assert sessao.revoked_at is not None
    assert sessao.revoked_reason == "logout"
    assert refresh and all(r.revoked_at is not None for r in refresh)


def test_logout_apaga_o_cookie_no_navegador(client):
    token, _ = _entrar(client)
    resposta = _sair(client, token)
    cookie = next(v for k, v in resposta.headers.multi_items() if k == "set-cookie").lower()
    assert cookie.startswith(f"{REFRESH_COOKIE_NAME}=")
    assert "max-age=0" in cookie
    assert "path=/api/v1/auth" in cookie


def test_logout_nao_afeta_as_outras_sessoes(client):
    token_a, _ = _entrar(client)
    _, sessao_b = _entrar(client)
    _sair(client, token_a)
    with get_sessionmaker()() as db:
        assert db.get(UserSession, sessao_b).revoked_at is None


def test_token_da_sessao_encerrada_deixa_de_valer(client):
    token, _ = _entrar(client)
    _sair(client, token)
    assert _sair(client, token).status_code == 401
