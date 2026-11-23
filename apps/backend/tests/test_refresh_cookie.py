"""REQ-20: refresh token só em cookie HttpOnly; Secure; SameSite=Strict."""

import uuid

import pytest
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.main import app
from app.services.token_service import REFRESH_COOKIE_NAME, hash_refresh_token

SENHA = "Senha-Forte#2026"


@pytest.fixture
def login(migrated_db):
    client = TestClient(app)
    email = f"cookie-{uuid.uuid4().hex[:10]}@teste.dev"
    client.post("/api/v1/auth/register", json={"name": "Ana", "email": email, "password": SENHA})
    return client.post("/api/v1/auth/login", json={"email": email, "password": SENHA})


def _cookie_header(resposta) -> str:
    cabecalhos = [v for k, v in resposta.headers.multi_items() if k == "set-cookie"]
    refresh = [c for c in cabecalhos if c.startswith(f"{REFRESH_COOKIE_NAME}=")]
    assert len(refresh) == 1
    return refresh[0]


def test_cookie_tem_todos_os_atributos_de_seguranca(login):
    cookie = _cookie_header(login).lower()
    assert "httponly" in cookie
    assert "secure" in cookie
    assert "samesite=strict" in cookie
    assert "path=/api/v1/auth" in cookie
    assert f"max-age={get_settings().refresh_token_ttl_seconds}" in cookie


def test_refresh_nunca_vai_no_corpo_da_resposta(login):
    valor = _cookie_header(login).split(";")[0].split("=", 1)[1]
    assert len(valor) >= 43
    assert valor not in login.text
    assert "refresh" not in login.json()


def test_valor_do_cookie_e_o_refresh_registrado(login):
    from sqlalchemy import select

    from app.db.models import RefreshToken
    from app.db.session import get_sessionmaker

    valor = _cookie_header(login).split(";")[0].split("=", 1)[1]
    with get_sessionmaker()() as db:
        assert db.scalar(select(RefreshToken).where(RefreshToken.token_sha256 == hash_refresh_token(valor)))
