"""REQ-27: o token é rejeitado se o User-Agent mudar."""

import uuid

import pytest
from fastapi import APIRouter
from fastapi.testclient import TestClient

from app.api.deps import CurrentUser
from app.crypto.jwt import decode_access_token
from app.crypto.keyed_hash import keyed_hash
from app.main import create_app

SENHA = "Senha-Forte#2026"
NAVEGADOR = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/140.0"

router = APIRouter()


@router.get("/api/v1/_teste/eu")
def _eu(user: CurrentUser):
    return {"id": str(user.id)}


@pytest.fixture(scope="module")
def client(migrated_db):
    app = create_app()
    app.include_router(router)
    return TestClient(app)


@pytest.fixture
def token(client):
    email = f"ua-{uuid.uuid4().hex[:10]}@teste.dev"
    client.post("/api/v1/auth/register", json={"name": "Ana", "email": email, "password": SENHA})
    resposta = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": SENHA},
        headers={"User-Agent": NAVEGADOR},
    )
    return resposta.json()["access_token"]


def _get(client, token, ua):
    return client.get("/api/v1/_teste/eu", headers={"Authorization": f"Bearer {token}", "User-Agent": ua})


def test_claim_ua_hash_e_o_hmac_do_user_agent_do_login(token):
    claims = decode_access_token(token)
    assert claims["ua_hash"] == keyed_hash(NAVEGADOR)
    assert NAVEGADOR not in str(claims)


def test_mesmo_user_agent_e_aceito(client, token):
    assert _get(client, token, NAVEGADOR).status_code == 200


@pytest.mark.parametrize(
    "outro", ["curl/8.10.1", NAVEGADOR + " ", "", "Mozilla/5.0 (X11; Linux) Firefox/130"]
)
def test_user_agent_diferente_e_rejeitado(client, token, outro):
    resposta = _get(client, token, outro)
    assert resposta.status_code == 401
    assert resposta.json()["code"] == "AUTH_004"
