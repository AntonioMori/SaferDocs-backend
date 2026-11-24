"""REQ-15: com 2FA ativo, nenhum JWT ou cookie é emitido antes do código TOTP."""

import hashlib
import time
import uuid
from datetime import UTC, datetime, timedelta

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app.crypto.jwt import decode_access_token
from app.db.models import MfaChallenge, User
from app.db.session import get_sessionmaker
from app.main import app
from app.services.token_service import REFRESH_COOKIE_NAME

SENHA = "Senha-Forte#2026"


@pytest.fixture
def client(migrated_db):
    return TestClient(app)


@pytest.fixture
def conta(client):
    """Conta com 2FA ativo. Devolve e-mail, id e o gerador de códigos (o "app")."""
    email = f"mfa-{uuid.uuid4().hex[:10]}@teste.dev"
    user_id = client.post(
        "/api/v1/auth/register", json={"name": "Ana", "email": email, "password": SENHA}
    ).json()["id"]
    token = client.post("/api/v1/auth/login", json={"email": email, "password": SENHA}).json()["access_token"]
    h = {"Authorization": f"Bearer {token}"}
    app_totp = pyotp.parse_uri(client.post("/api/v1/auth/2fa/setup", headers=h).json()["otpauth_uri"])
    assert client.post("/api/v1/auth/2fa/enable", json={"code": app_totp.now()}, headers=h).status_code == 200
    client.cookies.clear()
    return {"email": email, "id": user_id, "app": app_totp}


def _senha(client, conta, senha=SENHA):
    return client.post("/api/v1/auth/login", json={"email": conta["email"], "password": senha})


def _proximo(conta, n=1) -> str:
    """Código de uma janela à frente (a atual já foi usada na ativação)."""
    return conta["app"].at(time.time() + 30 * n)


def _errado(conta) -> str:
    validos = {conta["app"].at(time.time() + 30 * d) for d in (-1, 0, 1)}
    return next(f"{i:06d}" for i in range(1_000_000) if f"{i:06d}" not in validos)


def _totp(client, mfa_token, code):
    return client.post("/api/v1/auth/login/totp", json={"mfa_token": mfa_token, "code": code})


# ------------------------------------------------------------------ primeiro passo


def test_senha_certa_devolve_so_o_desafio(client, conta):
    resposta = _senha(client, conta)
    assert resposta.status_code == 200
    corpo = resposta.json()
    assert corpo["mfa_required"] is True and corpo["mfa_token"]
    assert "access_token" not in corpo
    assert REFRESH_COOKIE_NAME not in resposta.cookies
    assert "set-cookie" not in resposta.headers


def test_mfa_token_fica_no_banco_so_como_hash(client, conta):
    mfa_token = _senha(client, conta).json()["mfa_token"]
    with get_sessionmaker()() as db:
        desafio = db.scalar(select(MfaChallenge).where(MfaChallenge.user_id == uuid.UUID(conta["id"])))
    assert desafio.token_sha256 == hashlib.sha256(mfa_token.encode()).hexdigest()
    assert desafio.expires_at - desafio.created_at <= timedelta(minutes=5, seconds=1)


def test_mfa_token_nao_vale_como_access_token(client, conta):
    mfa_token = _senha(client, conta).json()["mfa_token"]
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {mfa_token}"}).status_code == 401


def test_senha_errada_continua_com_a_mensagem_unica(client, conta):
    assert _senha(client, conta, "errada").json()["code"] == "AUTH_001"


# ------------------------------------------------------------------ segundo passo


def test_codigo_valido_emite_jwt_e_cookie(client, conta):
    mfa_token = _senha(client, conta).json()["mfa_token"]
    resposta = _totp(client, mfa_token, _proximo(conta))
    assert resposta.status_code == 200
    assert decode_access_token(resposta.json()["access_token"])["sub"] == conta["id"]
    assert REFRESH_COOKIE_NAME in resposta.cookies
    assert resposta.json()["user"]["totp_enabled"] is True


def test_sem_codigo_valido_nenhum_cookie_ou_jwt(client, conta):
    mfa_token = _senha(client, conta).json()["mfa_token"]
    resposta = _totp(client, mfa_token, _errado(conta))
    assert resposta.status_code == 401
    assert resposta.json()["code"] == "AUTH_002"
    assert "access_token" not in resposta.json()
    assert "set-cookie" not in resposta.headers


def test_mfa_token_e_de_uso_unico(client, conta):
    mfa_token = _senha(client, conta).json()["mfa_token"]
    assert _totp(client, mfa_token, _proximo(conta)).status_code == 200
    assert _totp(client, mfa_token, _proximo(conta, -1)).status_code == 401


def test_codigo_ja_usado_nao_serve_em_outro_login(client, conta):
    codigo = _proximo(conta)
    assert _totp(client, _senha(client, conta).json()["mfa_token"], codigo).status_code == 200
    assert _totp(client, _senha(client, conta).json()["mfa_token"], codigo).status_code == 401


def test_mfa_token_expirado_e_recusado(client, conta):
    mfa_token = _senha(client, conta).json()["mfa_token"]
    with get_sessionmaker()() as db:
        db.execute(
            update(MfaChallenge)
            .where(MfaChallenge.token_sha256 == hashlib.sha256(mfa_token.encode()).hexdigest())
            .values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
        db.commit()
    assert _totp(client, mfa_token, _proximo(conta)).status_code == 401


def test_mfa_token_inventado_e_recusado(client, conta):
    assert _totp(client, "inventado", _proximo(conta)).json()["code"] == "AUTH_002"


# ------------------------------------------------------------------ bloqueio (REQ-03)


def test_falhas_do_totp_contam_para_o_bloqueio(client, conta):
    errado = _errado(conta)
    for _ in range(5):
        _totp(client, _senha(client, conta).json()["mfa_token"], errado)
    with get_sessionmaker()() as db:
        user = db.get(User, uuid.UUID(conta["id"]))
        assert user.locked_until is not None and user.locked_until > datetime.now(UTC)
    # Bloqueada: nem a senha certa passa.
    assert _senha(client, conta).json()["code"] == "AUTH_001"


def test_desafio_aguenta_poucas_tentativas(client, conta):
    mfa_token = _senha(client, conta).json()["mfa_token"]
    errado = _errado(conta)
    for _ in range(4):
        _totp(client, mfa_token, errado)
    # Na quinta falha a conta bloqueia e o desafio deixa de valer, mesmo com o código certo.
    _totp(client, mfa_token, errado)
    assert _totp(client, mfa_token, _proximo(conta)).status_code == 401


def test_conta_sem_2fa_continua_recebendo_o_token_direto(client):
    email = f"sem2fa-{uuid.uuid4().hex[:10]}@teste.dev"
    client.post("/api/v1/auth/register", json={"name": "Ana", "email": email, "password": SENHA})
    corpo = client.post("/api/v1/auth/login", json={"email": email, "password": SENHA}).json()
    assert "access_token" in corpo and "mfa_required" not in corpo
