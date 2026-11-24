"""REQ-13: ativação do 2FA com QR Code (otpauth://) compatível com Google Authenticator e Authy."""

import time
import uuid
from urllib.parse import parse_qs, unquote, urlparse

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db.models import AuditLog, User
from app.db.session import get_sessionmaker
from app.main import app

SENHA = "Senha-Forte#2026"


@pytest.fixture
def client(migrated_db):
    return TestClient(app)


@pytest.fixture
def conta(client):
    email = f"2fa-{uuid.uuid4().hex[:10]}@teste.dev"
    client.post("/api/v1/auth/register", json={"name": "Ana", "email": email, "password": SENHA})
    token = client.post("/api/v1/auth/login", json={"email": email, "password": SENHA}).json()["access_token"]
    return {"email": email, "h": {"Authorization": f"Bearer {token}"}}


def _setup(client, conta) -> dict:
    resposta = client.post("/api/v1/auth/2fa/setup", headers=conta["h"])
    assert resposta.status_code == 200
    return resposta.json()


def _codigo(uri: str, deslocamento: int = 0) -> str:
    """O que o app autenticador faz: lê o QR (a URI) e gera o código."""
    return pyotp.parse_uri(uri).at(time.time() + 30 * deslocamento)


def _ativar(client, conta) -> str:
    uri = _setup(client, conta)["otpauth_uri"]
    resposta = client.post("/api/v1/auth/2fa/enable", json={"code": _codigo(uri)}, headers=conta["h"])
    assert resposta.status_code == 200
    return uri


def _ativo(client, conta) -> bool:
    return client.get("/api/v1/auth/me", headers=conta["h"]).json()["totp_enabled"]


def _eventos(client, conta) -> list[str]:
    return [e["type"] for e in client.get("/api/v1/security/events", headers=conta["h"]).json()]


# ------------------------------------------------------------------ setup


def test_setup_devolve_uri_otpauth_no_formato_dos_apps(client, conta):
    corpo = _setup(client, conta)
    uri = urlparse(corpo["otpauth_uri"])
    params = parse_qs(uri.query)
    assert (uri.scheme, uri.netloc) == ("otpauth", "totp")
    assert unquote(uri.path) == f"/SaferDocs:{conta['email']}"
    assert params["issuer"] == ["SaferDocs"]
    assert params["secret"] == [corpo["secret"]]
    assert params.get("period", ["30"]) == ["30"] and params.get("digits", ["6"]) == ["6"]


def test_setup_sozinho_nao_ativa_o_2fa(client, conta):
    _setup(client, conta)
    assert _ativo(client, conta) is False


def test_app_le_o_qr_e_gera_codigos_aceitos(client, conta):
    _ativar(client, conta)
    assert _ativo(client, conta) is True


def test_novo_setup_troca_o_segredo_pendente(client, conta):
    antigo = _setup(client, conta)["otpauth_uri"]
    _setup(client, conta)
    resposta = client.post("/api/v1/auth/2fa/enable", json={"code": _codigo(antigo)}, headers=conta["h"])
    assert resposta.status_code == 400


# ------------------------------------------------------------------ enable


def test_codigo_errado_nao_ativa(client, conta):
    uri = _setup(client, conta)["otpauth_uri"]
    errado = f"{(int(_codigo(uri)) + 1) % 1_000_000:06d}"
    resposta = client.post("/api/v1/auth/2fa/enable", json={"code": errado}, headers=conta["h"])
    assert resposta.status_code == 400
    assert resposta.json()["fields"][0]["field"] == "code"
    assert _ativo(client, conta) is False


def test_enable_sem_setup_e_recusado(client, conta):
    resposta = client.post("/api/v1/auth/2fa/enable", json={"code": "123456"}, headers=conta["h"])
    assert resposta.status_code == 400


def test_ativacao_e_registrada_na_auditoria_e_na_atividade(client, conta):
    _ativar(client, conta)
    assert "TOTP_ENABLED" in _eventos(client, conta)
    with get_sessionmaker()() as db:
        user = db.scalar(select(User).where(User.email == conta["email"]))
        acoes = db.scalars(select(AuditLog.action).where(AuditLog.user_id == user.id)).all()
    assert "TOTP_ENABLED" in acoes


def test_setup_com_2fa_ativo_e_recusado(client, conta):
    _ativar(client, conta)
    assert client.post("/api/v1/auth/2fa/setup", headers=conta["h"]).status_code == 400


# ------------------------------------------------------------------ disable


def _desativar(client, conta, senha, codigo):
    return client.post(
        "/api/v1/auth/2fa/disable", json={"password": senha, "code": codigo}, headers=conta["h"]
    )


def test_desativar_exige_senha_correta(client, conta):
    uri = _ativar(client, conta)
    resposta = _desativar(client, conta, "errada", _codigo(uri, 1))
    assert resposta.status_code == 400
    assert _ativo(client, conta) is True


def test_desativar_exige_codigo_valido_e_nao_reaproveita_o_da_ativacao(client, conta):
    uri = _ativar(client, conta)
    assert _desativar(client, conta, SENHA, _codigo(uri)).status_code == 400  # já usado no enable
    assert _ativo(client, conta) is True


def test_desativar_apaga_o_segredo_e_avisa_o_usuario(client, conta):
    uri = _ativar(client, conta)
    assert _desativar(client, conta, SENHA, _codigo(uri, 1)).status_code == 204
    assert _ativo(client, conta) is False
    assert "TOTP_DISABLED" in _eventos(client, conta)
    with get_sessionmaker()() as db:
        user = db.scalar(select(User).where(User.email == conta["email"]))
        assert user.totp_secret_enc is None and user.totp_last_step is None


@pytest.mark.parametrize("rota", ["setup", "enable", "disable"])
def test_rotas_exigem_autenticacao(client, rota):
    assert client.post(f"/api/v1/auth/2fa/{rota}", json={}).status_code == 401
