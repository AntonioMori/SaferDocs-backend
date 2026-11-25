"""REQ-30: reusar um refresh token derruba toda a família de sessões do usuário."""

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.crypto.jwt import decode_access_token
from app.db.models import RefreshToken, UserSession
from app.db.session import get_sessionmaker
from app.main import app
from app.services import audit_service
from app.services.token_service import REFRESH_COOKIE_NAME

SENHA = "Senha-Forte#2026"


def _cookie(resposta) -> str | None:
    for chave, valor in resposta.headers.multi_items():
        if chave == "set-cookie" and valor.startswith(f"{REFRESH_COOKIE_NAME}="):
            return valor.split(";")[0].split("=", 1)[1].strip('"') or None
    return None


@pytest.fixture
def client(migrated_db):
    return TestClient(app, headers={"Origin": "http://localhost:3039"})  # o front manda Origin (REQ-65)


@pytest.fixture
def conta(client):
    email = f"reuse-{uuid.uuid4().hex[:10]}@teste.dev"
    user_id = client.post(
        "/api/v1/auth/register", json={"name": "Ana", "email": email, "password": SENHA}
    ).json()["id"]
    return {"email": email, "id": uuid.UUID(user_id)}


def _login(client, email):
    resposta = client.post("/api/v1/auth/login", json={"email": email, "password": SENHA})
    return {"access": resposta.json()["access_token"], "refresh": _cookie(resposta)}


def _refresh(client, valor):
    client.cookies.clear()
    client.cookies.set(REFRESH_COOKIE_NAME, valor, path="/api/v1/auth")
    return client.post("/api/v1/auth/refresh")


def _logout(client, access):
    return client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {access}"})


def test_reuso_derruba_todas_as_sessoes_do_usuario(client, conta):
    celular = _login(client, conta["email"])
    notebook = _login(client, conta["email"])

    trocado = _refresh(client, celular["refresh"])  # uso legítimo
    assert trocado.status_code == 200

    reuso = _refresh(client, celular["refresh"])  # o mesmo token de novo: comprometido
    assert reuso.status_code == 401
    assert reuso.json()["code"] == "AUTH_005"

    with get_sessionmaker()() as db:
        sessoes = db.scalars(select(UserSession).where(UserSession.user_id == conta["id"])).all()
        assert sessoes and all(s.revoked_at is not None for s in sessoes)
        assert {s.revoked_reason for s in sessoes} == {"refresh_reuse"}
        ids = [s.id for s in sessoes]
        refresh_ativos = db.scalars(
            select(RefreshToken).where(RefreshToken.session_id.in_(ids), RefreshToken.revoked_at.is_(None))
        ).all()
        assert refresh_ativos == []

    # Nada mais vale: nem o par novo do celular, nem o notebook.
    assert _refresh(client, _cookie(trocado)).status_code == 401
    assert _logout(client, trocado.json()["access_token"]).json()["code"] == "AUTH_004"
    assert _logout(client, notebook["access"]).json()["code"] == "AUTH_004"


def test_reuso_nao_afeta_outros_usuarios(client, conta):
    outro_email = f"reuse-{uuid.uuid4().hex[:10]}@teste.dev"
    client.post("/api/v1/auth/register", json={"name": "Bia", "email": outro_email, "password": SENHA})
    outro = _login(client, outro_email)

    meu = _login(client, conta["email"])
    _refresh(client, meu["refresh"])
    _refresh(client, meu["refresh"])

    assert _logout(client, outro["access"]).status_code == 204


def test_reuso_e_registrado_na_auditoria(client, conta, monkeypatch):
    acoes = []
    original = audit_service.record

    def espiao(db, **kw):
        acoes.append(kw["action"])
        return original(db, **kw)

    monkeypatch.setattr(audit_service, "record", espiao)
    login = _login(client, conta["email"])
    _refresh(client, login["refresh"])
    _refresh(client, login["refresh"])
    assert audit_service.AuditAction.REFRESH_TOKEN_REUSE in acoes


def test_reuso_apaga_o_cookie(client, conta):
    login = _login(client, conta["email"])
    _refresh(client, login["refresh"])
    reuso = _refresh(client, login["refresh"])
    cookie = next(v for k, v in reuso.headers.multi_items() if k == "set-cookie").lower()
    assert "max-age=0" in cookie
    assert decode_access_token(login["access"])  # o token decodifica, mas a sessão já caiu
