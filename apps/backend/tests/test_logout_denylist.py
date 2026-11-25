"""REQ-21: no logout o jti vai para a denylist com a validade restante."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.crypto.jwt import decode_access_token
from app.db.models import JwtDenylist
from app.db.session import get_sessionmaker
from app.main import app
from app.services.session_service import deny_access_token

SENHA = "Senha-Forte#2026"


@pytest.fixture
def client(migrated_db):
    return TestClient(app, headers={"Origin": "http://localhost:3039"})  # o front manda Origin (REQ-65)


@pytest.fixture
def token(client):
    email = f"out-{uuid.uuid4().hex[:10]}@teste.dev"
    client.post("/api/v1/auth/register", json={"name": "Ana", "email": email, "password": SENHA})
    return client.post("/api/v1/auth/login", json={"email": email, "password": SENHA}).json()["access_token"]


def _logout(client, token):
    return client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})


def test_logout_coloca_o_jti_na_denylist_com_a_validade_restante(client, token):
    claims = decode_access_token(token)
    assert _logout(client, token).status_code == 204
    with get_sessionmaker()() as db:
        registro = db.get(JwtDenylist, claims["jti"])
    assert registro is not None
    assert registro.expires_at == datetime.fromtimestamp(claims["exp"], tz=UTC)


def test_logout_exige_autenticacao(client):
    resposta = client.post("/api/v1/auth/logout")
    assert resposta.status_code == 401
    assert resposta.json()["code"] == "AUTH_003"


def test_mesmo_jti_duas_vezes_nao_quebra(migrated_db):
    claims = {"jti": str(uuid.uuid4()), "exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp())}
    with get_sessionmaker()() as db:
        deny_access_token(db, claims)
        deny_access_token(db, claims)
        db.commit()
        assert db.get(JwtDenylist, claims["jti"]) is not None


def test_entradas_vencidas_sao_limpas(migrated_db):
    vencido = {"jti": str(uuid.uuid4()), "exp": int((datetime.now(UTC) - timedelta(minutes=1)).timestamp())}
    novo = {"jti": str(uuid.uuid4()), "exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp())}
    with get_sessionmaker()() as db:
        db.add(JwtDenylist(jti=vencido["jti"], expires_at=datetime.fromtimestamp(vencido["exp"], tz=UTC)))
        db.commit()
        deny_access_token(db, novo)
        db.commit()
        assert db.get(JwtDenylist, vencido["jti"]) is None
        assert db.get(JwtDenylist, novo["jti"]) is not None
