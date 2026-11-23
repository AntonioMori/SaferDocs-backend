"""REQ-26: claim ip (hash) e alerta, sem rejeitar, quando o IP muda."""

import uuid

import pytest
from fastapi import APIRouter
from fastapi.testclient import TestClient

from app.api.deps import CurrentUser
from app.crypto.jwt import decode_access_token
from app.crypto.keyed_hash import keyed_hash
from app.db.models import SecurityEvent
from app.main import create_app
from app.services import audit_service, security_events

SENHA = "Senha-Forte#2026"
IP_LOGIN = "203.0.113.10"
IP_OUTRO = "198.51.100.77"

router = APIRouter()


@router.get("/api/v1/_teste/eu")
def _eu(user: CurrentUser):
    return {"id": str(user.id)}


@pytest.fixture(scope="module")
def app_teste(migrated_db):
    app = create_app()
    app.include_router(router)
    return app


@pytest.fixture
def token(app_teste):
    client = TestClient(app_teste, client=(IP_LOGIN, 5000))
    email = f"ip-{uuid.uuid4().hex[:10]}@teste.dev"
    client.post("/api/v1/auth/register", json={"name": "Ana", "email": email, "password": SENHA})
    return client.post("/api/v1/auth/login", json={"email": email, "password": SENHA}).json()["access_token"]


@pytest.fixture
def auditoria(monkeypatch):
    registros = []
    monkeypatch.setattr(audit_service, "record", lambda db, **kw: registros.append(kw["action"]))
    return registros


@pytest.fixture
def eventos_persistidos(monkeypatch):
    """Simula a versão real do emit (REQ-58), que grava em security_events."""

    def emit(db, *, user_id, type, request, details=None):  # noqa: A002
        db.add(SecurityEvent(user_id=user_id, type=type, details=details))

    monkeypatch.setattr(security_events, "emit", emit)


def _get(app, token, ip):
    return TestClient(app, client=(ip, 5000)).get(
        "/api/v1/_teste/eu", headers={"Authorization": f"Bearer {token}"}
    )


def test_claim_ip_e_o_hmac_do_ip_do_login(token):
    claims = decode_access_token(token)
    assert claims["ip"] == keyed_hash(IP_LOGIN)
    assert IP_LOGIN not in str(claims)


def test_mesmo_ip_nao_gera_alerta(app_teste, token, auditoria):
    assert _get(app_teste, token, IP_LOGIN).status_code == 200
    assert audit_service.AuditAction.IP_MISMATCH not in auditoria


def test_ip_diferente_continua_aceito_mas_gera_alerta(app_teste, token, auditoria):
    assert _get(app_teste, token, IP_OUTRO).status_code == 200
    assert auditoria.count(audit_service.AuditAction.IP_MISMATCH) == 1


def test_alerta_sai_uma_vez_por_sessao_e_ip(app_teste, token, auditoria, eventos_persistidos):
    for _ in range(3):
        assert _get(app_teste, token, IP_OUTRO).status_code == 200
    assert auditoria.count(audit_service.AuditAction.IP_MISMATCH) == 1
    _get(app_teste, token, "192.0.2.200")  # um terceiro IP gera um novo alerta
    assert auditoria.count(audit_service.AuditAction.IP_MISMATCH) == 2
