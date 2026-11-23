"""REQ-22 e Figura 4: verificações de toda requisição autenticada."""

import uuid
from datetime import UTC, datetime

import pytest
from fastapi import APIRouter
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from app.api.deps import PUBLIC_ROUTES, CurrentUser, get_auth_context
from app.crypto.jwt import decode_access_token
from app.db.models import JwtDenylist, UserSession
from app.db.session import get_sessionmaker
from app.main import app as app_real
from app.main import create_app
from app.services.auth_service import find_user_by_email

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
    email = f"chain-{uuid.uuid4().hex[:10]}@teste.dev"
    client.post("/api/v1/auth/register", json={"name": "Ana", "email": email, "password": SENHA})
    token = client.post("/api/v1/auth/login", json={"email": email, "password": SENHA}).json()["access_token"]
    return {"email": email, "token": token, "claims": decode_access_token(token)}


def _get(client, token, **headers):
    return client.get("/api/v1/_teste/eu", headers={"Authorization": f"Bearer {token}", **headers})


def _codigo(resposta):
    assert resposta.status_code == 401
    return resposta.json()["code"]


def test_token_valido_passa_por_toda_a_cadeia(client, conta):
    assert _get(client, conta["token"]).status_code == 200


def test_1_assinatura_invalida(client, conta):
    cabecalho, corpo, assinatura = conta["token"].split(".")
    adulterado = f"{cabecalho}.{corpo}.{assinatura[:-4]}AAAA"
    assert _codigo(_get(client, adulterado)) == "AUTH_003"


def test_2_jti_na_denylist_e_rejeitado_mesmo_com_sessao_ativa(client, conta):
    with get_sessionmaker()() as db:
        db.add(
            JwtDenylist(
                jti=conta["claims"]["jti"], expires_at=datetime.fromtimestamp(conta["claims"]["exp"], UTC)
            )
        )
        db.commit()
        assert db.get(UserSession, uuid.UUID(conta["claims"]["session_id"])).revoked_at is None
    assert _codigo(_get(client, conta["token"])) == "AUTH_004"


def test_2_logout_revoga_o_token_imediatamente(client, conta):
    assert (
        client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {conta['token']}"}).status_code
        == 204
    )
    assert _codigo(_get(client, conta["token"])) == "AUTH_004"


def test_3_emitido_antes_da_troca_de_senha(client, conta):
    with get_sessionmaker()() as db:
        user = find_user_by_email(db, conta["email"])
        user.password_changed_at = datetime.fromtimestamp(conta["claims"]["iat"] + 1, UTC)
        db.commit()
    assert _codigo(_get(client, conta["token"])) == "AUTH_004"


def test_4_user_agent_diferente(client, conta):
    assert _codigo(_get(client, conta["token"], **{"User-Agent": "curl/8.0"})) == "AUTH_004"


def test_5_sessao_revogada(client, conta):
    with get_sessionmaker()() as db:
        db.get(UserSession, uuid.UUID(conta["claims"]["session_id"])).revoked_at = datetime.now(UTC)
        db.commit()
    assert _codigo(_get(client, conta["token"])) == "AUTH_004"


# ------------------------------------------------------------------ centralização


def _usa_a_cadeia(dependant) -> bool:
    return any(d.call is get_auth_context or _usa_a_cadeia(d) for d in dependant.dependencies)


def test_toda_rota_nao_publica_passa_pela_cadeia_de_autenticacao():
    desprotegidas = []
    for rota in app_real.routes:
        if not isinstance(rota, APIRoute):
            continue
        for metodo in rota.methods:
            if (metodo, rota.path) not in PUBLIC_ROUTES and not _usa_a_cadeia(rota.dependant):
                desprotegidas.append(f"{metodo} {rota.path}")
    assert desprotegidas == [], f"Rotas sem autenticação fora de PUBLIC_ROUTES: {desprotegidas}"
