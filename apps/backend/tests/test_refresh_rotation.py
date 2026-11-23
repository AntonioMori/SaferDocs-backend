"""REQ-29: cada uso do refresh token emite um par novo e invalida o anterior."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.crypto.jwt import decode_access_token
from app.db.models import RefreshToken
from app.db.session import get_sessionmaker
from app.main import app
from app.services.token_service import REFRESH_COOKIE_NAME, hash_refresh_token

SENHA = "Senha-Forte#2026"


def _cookie(resposta) -> str | None:
    for chave, valor in resposta.headers.multi_items():
        if chave == "set-cookie" and valor.startswith(f"{REFRESH_COOKIE_NAME}="):
            return valor.split(";")[0].split("=", 1)[1].strip('"') or None
    return None


@pytest.fixture
def client(migrated_db):
    return TestClient(app)


@pytest.fixture
def login(client):
    email = f"rot-{uuid.uuid4().hex[:10]}@teste.dev"
    client.post("/api/v1/auth/register", json={"name": "Ana", "email": email, "password": SENHA})
    resposta = client.post("/api/v1/auth/login", json={"email": email, "password": SENHA})
    return {"access": resposta.json()["access_token"], "refresh": _cookie(resposta)}


def _refresh(client, valor, **headers):
    client.cookies.clear()
    client.cookies.set(REFRESH_COOKIE_NAME, valor, path="/api/v1/auth")
    return client.post("/api/v1/auth/refresh", headers=headers)


def test_refresh_emite_par_novo_na_mesma_sessao(client, login):
    resposta = _refresh(client, login["refresh"])
    assert resposta.status_code == 200
    novo_access = resposta.json()["access_token"]
    novo_refresh = _cookie(resposta)
    assert novo_refresh and novo_refresh != login["refresh"]
    assert novo_access != login["access"]
    antes, depois = decode_access_token(login["access"]), decode_access_token(novo_access)
    assert antes["session_id"] == depois["session_id"]
    assert antes["jti"] != depois["jti"]
    assert novo_refresh not in resposta.text  # refresh só no cookie (REQ-20)


def test_refresh_anterior_fica_invalidado_no_banco(client, login):
    _refresh(client, login["refresh"])
    with get_sessionmaker()() as db:
        antigo = db.scalar(
            select(RefreshToken).where(RefreshToken.token_sha256 == hash_refresh_token(login["refresh"]))
        )
    assert antigo.used_at is not None


def test_cada_refresh_vale_uma_vez_e_a_cadeia_continua(client, login):
    r1 = _refresh(client, login["refresh"])
    r2 = _refresh(client, _cookie(r1))
    assert r2.status_code == 200
    assert _refresh(client, _cookie(r1)).status_code == 401  # já usado


@pytest.mark.parametrize("valor", [None, "", "token-que-nao-existe"])
def test_refresh_ausente_ou_desconhecido(client, valor):
    client.cookies.clear()
    if valor is not None:
        client.cookies.set(REFRESH_COOKIE_NAME, valor, path="/api/v1/auth")
    resposta = client.post("/api/v1/auth/refresh")
    assert resposta.status_code == 401
    assert resposta.json()["code"] == "AUTH_005"


def test_refresh_expirado_e_recusado_e_o_cookie_apagado(client, login):
    with get_sessionmaker()() as db:
        registro = db.scalar(
            select(RefreshToken).where(RefreshToken.token_sha256 == hash_refresh_token(login["refresh"]))
        )
        registro.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
    resposta = _refresh(client, login["refresh"])
    assert resposta.status_code == 401
    cookie = next(v for k, v in resposta.headers.multi_items() if k == "set-cookie").lower()
    assert "max-age=0" in cookie


def test_refresh_de_sessao_encerrada_e_recusado(client, login):
    client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {login['access']}"})
    assert _refresh(client, login["refresh"]).status_code == 401


def test_refresh_com_outro_user_agent_e_recusado(client, login):
    assert _refresh(client, login["refresh"], **{"User-Agent": "curl/8.0"}).status_code == 401
