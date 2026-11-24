"""REQ-14: códigos de recuperação de uso único, mostrados uma vez e guardados como HMAC."""

import time
import uuid

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db.models import AuditLog, RecoveryCode
from app.db.session import get_sessionmaker
from app.main import app
from app.services.token_service import REFRESH_COOKIE_NAME

SENHA = "Senha-Forte#2026"


@pytest.fixture
def client(migrated_db):
    return TestClient(app)


@pytest.fixture
def conta(client):
    email = f"rec-{uuid.uuid4().hex[:10]}@teste.dev"
    user_id = client.post(
        "/api/v1/auth/register", json={"name": "Ana", "email": email, "password": SENHA}
    ).json()["id"]
    token = client.post("/api/v1/auth/login", json={"email": email, "password": SENHA}).json()["access_token"]
    h = {"Authorization": f"Bearer {token}"}
    app_totp = pyotp.parse_uri(client.post("/api/v1/auth/2fa/setup", headers=h).json()["otpauth_uri"])
    resposta = client.post("/api/v1/auth/2fa/enable", json={"code": app_totp.now()}, headers=h)
    client.cookies.clear()
    return {
        "email": email,
        "id": uuid.UUID(user_id),
        "h": h,
        "app": app_totp,
        "codigos": resposta.json()["recovery_codes"],
    }


def _mfa_token(client, conta) -> str:
    return client.post("/api/v1/auth/login", json={"email": conta["email"], "password": SENHA}).json()[
        "mfa_token"
    ]


def _com_recuperacao(client, conta, codigo):
    return client.post(
        "/api/v1/auth/login/totp", json={"mfa_token": _mfa_token(client, conta), "recovery_code": codigo}
    )


def _registros(conta) -> list[RecoveryCode]:
    with get_sessionmaker()() as db:
        return list(db.scalars(select(RecoveryCode).where(RecoveryCode.user_id == conta["id"])))


# ------------------------------------------------------------------ geração


def test_ativacao_mostra_dez_codigos_distintos(conta):
    codigos = conta["codigos"]
    assert len(codigos) == len(set(codigos)) == 10
    assert all(len(c) == 14 and c.count("-") == 2 for c in codigos)


def test_banco_guarda_so_o_hmac(conta):
    registros = _registros(conta)
    assert len(registros) == 10
    guardados = {r.code_hmac for r in registros}
    for codigo in conta["codigos"]:
        assert codigo not in guardados and codigo.replace("-", "") not in guardados
    assert all(len(h) == 64 for h in guardados)


# ------------------------------------------------------------------ uso no login


def test_codigo_de_recuperacao_substitui_o_totp_no_login(client, conta):
    resposta = _com_recuperacao(client, conta, conta["codigos"][0])
    assert resposta.status_code == 200
    assert resposta.json()["access_token"]
    assert REFRESH_COOKIE_NAME in resposta.cookies


def test_codigo_usado_nao_funciona_de_novo(client, conta):
    assert _com_recuperacao(client, conta, conta["codigos"][0]).status_code == 200
    resposta = _com_recuperacao(client, conta, conta["codigos"][0])
    assert resposta.status_code == 401
    assert resposta.json()["code"] == "AUTH_002"
    assert _com_recuperacao(client, conta, conta["codigos"][1]).status_code == 200  # os outros seguem valendo


def test_aceita_minusculas_e_sem_hifens(client, conta):
    assert _com_recuperacao(client, conta, conta["codigos"][2].replace("-", "").lower()).status_code == 200


def test_codigo_inventado_conta_como_falha(client, conta):
    assert _com_recuperacao(client, conta, "AAAA-BBBB-CCCC").status_code == 401
    with get_sessionmaker()() as db:
        acoes = db.scalars(select(AuditLog.action).where(AuditLog.user_id == conta["id"])).all()
    assert "TOTP_FAILURE" in acoes


def test_uso_e_registrado_na_auditoria(client, conta):
    _com_recuperacao(client, conta, conta["codigos"][0])
    with get_sessionmaker()() as db:
        acoes = db.scalars(select(AuditLog.action).where(AuditLog.user_id == conta["id"])).all()
    assert "RECOVERY_CODE_USED" in acoes


@pytest.mark.parametrize("corpo", [{}, {"code": "123456", "recovery_code": "AAAA-BBBB-CCCC"}])
def test_exige_exatamente_um_dos_dois(client, conta, corpo):
    resposta = client.post("/api/v1/auth/login/totp", json={"mfa_token": _mfa_token(client, conta), **corpo})
    assert resposta.status_code == 400
    assert resposta.json()["code"] == "VAL_001"


# ------------------------------------------------------------------ regenerar


def _regenerar(client, conta, codigo):
    return client.post("/api/v1/auth/2fa/recovery-codes", json={"code": codigo}, headers=conta["h"])


def test_regenerar_invalida_os_antigos(client, conta):
    resposta = _regenerar(client, conta, conta["app"].at(time.time() + 30))
    assert resposta.status_code == 200
    novos = resposta.json()["recovery_codes"]
    assert len(novos) == 10 and not set(novos) & set(conta["codigos"])
    assert _com_recuperacao(client, conta, conta["codigos"][0]).status_code == 401
    assert _com_recuperacao(client, conta, novos[0]).status_code == 200


def test_regenerar_exige_codigo_totp_valido(client, conta):
    assert _regenerar(client, conta, conta["app"].now()).status_code == 400  # já usado na ativação
    assert len(_registros(conta)) == 10


def test_desativar_o_2fa_apaga_os_codigos(client, conta):
    resposta = client.post(
        "/api/v1/auth/2fa/disable",
        json={"password": SENHA, "code": conta["app"].at(time.time() + 30)},
        headers=conta["h"],
    )
    assert resposta.status_code == 204
    assert _registros(conta) == []
