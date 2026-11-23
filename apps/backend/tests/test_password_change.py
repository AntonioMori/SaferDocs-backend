"""REQ-25: tokens emitidos antes da última troca de senha são rejeitados."""

import time
import uuid
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from app.crypto.jwt import decode_access_token
from app.db.session import get_sessionmaker
from app.main import app
from app.services.auth_service import find_user_by_email

SENHA = "Senha-Forte#2026"
NOVA = "Outra-Senha#2027"


@pytest.fixture
def client(migrated_db):
    return TestClient(app)


@pytest.fixture
def conta(client):
    email = f"pwd-{uuid.uuid4().hex[:10]}@teste.dev"
    client.post("/api/v1/auth/register", json={"name": "Ana", "email": email, "password": SENHA})
    return email


def _entrar(client, email, senha=SENHA):
    return client.post("/api/v1/auth/login", json={"email": email, "password": senha}).json()["access_token"]


def _trocar(client, token, atual=SENHA, nova=NOVA):
    return client.put(
        "/api/v1/auth/password",
        json={"current_password": atual, "new_password": nova},
        headers={"Authorization": f"Bearer {token}"},
    )


def _logout(client, token):
    return client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})


def test_troca_rejeita_tokens_antigos_e_mantem_o_usuario_logado(client, conta):
    neste_dispositivo = _entrar(client, conta)
    em_outro_dispositivo = _entrar(client, conta)
    time.sleep(1.1)  # tokens antigos com iat estritamente anterior à troca

    resposta = _trocar(client, neste_dispositivo)
    assert resposta.status_code == 200
    novo = resposta.json()["access_token"]

    for antigo in (neste_dispositivo, em_outro_dispositivo):
        rejeitado = _logout(client, antigo)
        assert rejeitado.status_code == 401
        assert rejeitado.json()["code"] == "AUTH_004"
    assert _logout(client, novo).status_code == 204


def test_iat_anterior_a_troca_e_rejeitado_mesmo_com_sessao_ativa(client, conta):
    token = _entrar(client, conta)
    iat = decode_access_token(token)["iat"]
    with get_sessionmaker()() as db:
        user = find_user_by_email(db, conta)
        user.password_changed_at = datetime.fromtimestamp(iat + 1, tz=UTC)
        db.commit()
    assert _logout(client, token).json()["code"] == "AUTH_004"


def test_nova_senha_passa_a_valer_e_a_antiga_nao(client, conta):
    _trocar(client, _entrar(client, conta))
    assert client.post("/api/v1/auth/login", json={"email": conta, "password": SENHA}).status_code == 401
    assert client.post("/api/v1/auth/login", json={"email": conta, "password": NOVA}).status_code == 200


def test_senha_atual_errada_e_recusada(client, conta):
    resposta = _trocar(client, _entrar(client, conta), atual="Errada-123#abc")
    assert resposta.status_code == 400
    assert resposta.json()["fields"] == [{"field": "current_password", "reason": "senha atual incorreta"}]


def test_nova_senha_precisa_cumprir_a_politica_e_ser_diferente(client, conta):
    token = _entrar(client, conta)
    fraca = _trocar(client, token, nova="fraca")
    assert fraca.json()["fields"][0]["field"] == "new_password"
    igual = _trocar(client, token, nova=SENHA)
    assert igual.json()["fields"] == [
        {"field": "new_password", "reason": "precisa ser diferente da senha atual"}
    ]
