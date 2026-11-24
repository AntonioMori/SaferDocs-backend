"""REQ-16: códigos TOTP inválidos vão para a auditoria e, repetidos, viram alerta para o usuário."""

import time
import uuid
from datetime import UTC, datetime, timedelta

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.db.models import AuditLog
from app.db.session import get_sessionmaker
from app.main import app

SENHA = "Senha-Forte#2026"


@pytest.fixture
def client(migrated_db):
    return TestClient(app)


@pytest.fixture
def conta(client):
    email = f"alerta-{uuid.uuid4().hex[:10]}@teste.dev"
    user_id = client.post(
        "/api/v1/auth/register", json={"name": "Ana", "email": email, "password": SENHA}
    ).json()["id"]
    token = client.post("/api/v1/auth/login", json={"email": email, "password": SENHA}).json()["access_token"]
    h = {"Authorization": f"Bearer {token}"}
    app_totp = pyotp.parse_uri(client.post("/api/v1/auth/2fa/setup", headers=h).json()["otpauth_uri"])
    client.post("/api/v1/auth/2fa/enable", json={"code": app_totp.now()}, headers=h)
    client.cookies.clear()
    return {"email": email, "id": uuid.UUID(user_id), "app": app_totp}


def _mfa_token(client, conta) -> str:
    return client.post("/api/v1/auth/login", json={"email": conta["email"], "password": SENHA}).json()[
        "mfa_token"
    ]


def _errar(client, conta, vezes: int) -> None:
    validos = {conta["app"].at(time.time() + 30 * d) for d in (-1, 0, 1)}
    errado = next(f"{i:06d}" for i in range(1_000_000) if f"{i:06d}" not in validos)
    for _ in range(vezes):
        resposta = client.post(
            "/api/v1/auth/login/totp", json={"mfa_token": _mfa_token(client, conta), "code": errado}
        )
        assert resposta.status_code == 401


def _entrar(client, conta) -> dict:
    resposta = client.post(
        "/api/v1/auth/login/totp",
        json={"mfa_token": _mfa_token(client, conta), "code": conta["app"].at(time.time() + 30)},
    )
    assert resposta.status_code == 200
    return resposta.json()


def _alertas(client, corpo) -> list[dict]:
    eventos = client.get(
        "/api/v1/security/events", headers={"Authorization": f"Bearer {corpo['access_token']}"}
    )
    return [e for e in eventos.json() if e["type"] == "TOTP_FAILURES"]


def test_cada_falha_vai_para_a_auditoria(client, conta):
    _errar(client, conta, 2)
    with get_sessionmaker()() as db:
        total = db.scalar(
            select(func.count()).where(AuditLog.user_id == conta["id"], AuditLog.action == "TOTP_FAILURE")
        )
    assert total == 2


def test_duas_falhas_nao_geram_alerta(client, conta):
    _errar(client, conta, 2)
    assert _alertas(client, _entrar(client, conta)) == []


def test_tres_falhas_geram_alerta_visto_no_proximo_login(client, conta):
    _errar(client, conta, 3)
    corpo = _entrar(client, conta)
    assert corpo["unseen_security_events"] == 2  # TOTP_ENABLED (da ativação) + TOTP_FAILURES
    alertas = _alertas(client, corpo)
    assert len(alertas) == 1 and alertas[0]["seen"] is False
    assert alertas[0]["details"]["failures"] == 3


def test_um_alerta_por_janela(client, conta):
    _errar(client, conta, 4)  # a quinta falha bloquearia a conta (REQ-03)
    assert len(_alertas(client, _entrar(client, conta))) == 1


def test_falhas_antigas_nao_contam(client, conta):
    with get_sessionmaker()() as db:
        antigo = datetime.now(UTC) - timedelta(minutes=20)
        for _ in range(2):
            db.add(
                AuditLog(
                    user_id=conta["id"],
                    ip="1.2.3.4",
                    user_agent="ua",
                    action="TOTP_FAILURE",
                    result="FAILURE",
                    occurred_at=antigo,
                )
            )
        db.commit()
    _errar(client, conta, 1)
    assert _alertas(client, _entrar(client, conta)) == []
