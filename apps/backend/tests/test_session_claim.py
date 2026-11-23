"""REQ-28: o token carrega o session_id e revogar a sessão invalida o token."""

import uuid
from datetime import UTC, datetime

import pytest
from fastapi import APIRouter
from fastapi.testclient import TestClient

from app.api.deps import CurrentUser
from app.crypto.jwt import decode_access_token, encode_access_token
from app.db.models import UserSession
from app.db.session import get_sessionmaker
from app.main import create_app
from tests.conftest import session_token

SENHA = "Senha-Forte#2026"

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
def conta(client):
    email = f"sess-{uuid.uuid4().hex[:10]}@teste.dev"
    user_id = client.post(
        "/api/v1/auth/register", json={"name": "Ana", "email": email, "password": SENHA}
    ).json()["id"]
    return {"email": email, "id": uuid.UUID(user_id)}


def _get(client, token):
    return client.get("/api/v1/_teste/eu", headers={"Authorization": f"Bearer {token}"})


def _revogar(session_id):
    with get_sessionmaker()() as db:
        db.get(UserSession, session_id).revoked_at = datetime.now(UTC)
        db.commit()


def test_login_cria_sessao_e_o_token_aponta_para_ela(client, conta):
    resposta = client.post("/api/v1/auth/login", json={"email": conta["email"], "password": SENHA})
    claims = decode_access_token(resposta.json()["access_token"])
    with get_sessionmaker()() as db:
        sessao = db.get(UserSession, uuid.UUID(claims["session_id"]))
        assert sessao.user_id == conta["id"]
        assert sessao.revoked_at is None
        assert sessao.user_agent == "testclient"
        assert len(sessao.ip_hmac) == len(sessao.ua_hmac) == 64  # HMAC, não o valor em claro
    assert _get(client, resposta.json()["access_token"]).status_code == 200


def test_cada_login_e_uma_sessao_diferente(client, conta):
    sessoes = {
        decode_access_token(
            client.post("/api/v1/auth/login", json={"email": conta["email"], "password": SENHA}).json()[
                "access_token"
            ]
        )["session_id"]
        for _ in range(2)
    }
    assert len(sessoes) == 2


def test_revogar_a_sessao_invalida_o_token_na_hora(client, conta):
    token = session_token(conta["id"])
    assert _get(client, token).status_code == 200
    _revogar(uuid.UUID(decode_access_token(token)["session_id"]))
    resposta = _get(client, token)
    assert resposta.status_code == 401
    assert resposta.json()["code"] == "AUTH_004"


def test_revogar_uma_sessao_nao_afeta_as_outras(client, conta):
    a, b = session_token(conta["id"]), session_token(conta["id"])
    _revogar(uuid.UUID(decode_access_token(a)["session_id"]))
    assert _get(client, a).status_code == 401
    assert _get(client, b).status_code == 200


def test_sessao_de_outro_usuario_e_recusada(client, conta):
    outro = session_token(conta["id"])
    sessao_alheia = decode_access_token(outro)["session_id"]
    token, _ = encode_access_token(uuid.uuid4(), {"session_id": sessao_alheia})
    assert _get(client, token).json()["code"] == "AUTH_004"


def test_sessao_inexistente_e_recusada(client, conta):
    token, _ = encode_access_token(conta["id"], {"session_id": str(uuid.uuid4())})
    assert _get(client, token).status_code == 401
