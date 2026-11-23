"""REQ-04: o login não diferencia usuário inexistente de senha errada."""

import uuid

import pytest
from fastapi.testclient import TestClient

from app.crypto import passwords
from app.crypto.jwt import decode_access_token
from app.main import app
from app.services import auth_service

SENHA = "Senha-Forte#2026"


@pytest.fixture
def client(migrated_db):
    return TestClient(app)


@pytest.fixture
def conta(client):
    email = f"login-{uuid.uuid4().hex[:10]}@teste.dev"
    resposta = client.post("/api/v1/auth/register", json={"name": "Ana", "email": email, "password": SENHA})
    assert resposta.status_code == 201
    return {"email": email, "id": resposta.json()["id"]}


def _login(client, email, senha):
    return client.post("/api/v1/auth/login", json={"email": email, "password": senha})


def _sem_variaveis(corpo: dict) -> dict:
    return {k: v for k, v in corpo.items() if k not in ("timestamp", "request_id")}


def test_login_com_sucesso_emite_access_token(client, conta):
    resposta = _login(client, conta["email"].upper(), SENHA)
    assert resposta.status_code == 200
    corpo = resposta.json()
    assert corpo["token_type"] == "Bearer"
    assert corpo["expires_in"] == 900
    assert corpo["user"]["email"] == conta["email"]
    assert decode_access_token(corpo["access_token"])["sub"] == conta["id"]


def test_usuario_inexistente_e_senha_errada_tem_resposta_identica(client, conta):
    inexistente = _login(client, f"ninguem-{uuid.uuid4().hex}@teste.dev", SENHA)
    senha_errada = _login(client, conta["email"], SENHA + "x")
    assert inexistente.status_code == senha_errada.status_code == 401
    assert _sem_variaveis(inexistente.json()) == _sem_variaveis(senha_errada.json())
    assert inexistente.json()["code"] == "AUTH_001"
    assert inexistente.headers.get("www-authenticate") == senha_errada.headers.get("www-authenticate")


def test_usuario_inexistente_tambem_executa_o_argon2(client, monkeypatch):
    chamadas = []
    original = passwords.verify_password

    def espiao(password_hash, senha):
        chamadas.append(password_hash)
        return original(password_hash, senha)

    monkeypatch.setattr(auth_service, "verify_password", espiao)
    _login(client, f"ninguem-{uuid.uuid4().hex}@teste.dev", SENHA)
    assert chamadas == [passwords.dummy_hash()]


def test_mensagem_nao_menciona_email_nem_senha_especificamente(client, conta):
    mensagem = _login(client, conta["email"], "errada").json()["message"].lower()
    assert "não existe" not in mensagem
    assert "não encontrado" not in mensagem
    assert "senha incorreta" not in mensagem
