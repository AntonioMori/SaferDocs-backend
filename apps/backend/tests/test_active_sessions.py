"""REQ-57: sessões ativas, encerrar uma e "sair de todos os dispositivos"."""

import uuid

import pytest
from fastapi.testclient import TestClient

from app.crypto.jwt import decode_access_token
from app.main import app

SENHA = "Senha-Forte#2026"


@pytest.fixture
def client(migrated_db):
    return TestClient(app)


@pytest.fixture
def email(client):
    email = f"ses-{uuid.uuid4().hex[:10]}@teste.dev"
    client.post("/api/v1/auth/register", json={"name": "Ana", "email": email, "password": SENHA})
    return email


def _login(client, email):
    return client.post("/api/v1/auth/login", json={"email": email, "password": SENHA}).json()["access_token"]


def _h(token):
    return {"Authorization": f"Bearer {token}"}


def test_lista_sessoes_ativas_com_a_atual_marcada(client, email):
    a, b = _login(client, email), _login(client, email)
    resposta = client.get("/api/v1/sessions", headers=_h(a))
    assert resposta.status_code == 200
    sessoes = resposta.json()
    assert len(sessoes) == 2
    atual = [s for s in sessoes if s["current"]]
    assert len(atual) == 1 and atual[0]["id"] == decode_access_token(a)["session_id"]
    assert {"id", "user_agent", "ip", "created_at", "last_seen_at", "current"} == set(sessoes[0])
    del b


def test_encerrar_outra_sessao(client, email):
    a, b = _login(client, email), _login(client, email)
    sessao_b = decode_access_token(b)["session_id"]
    assert client.delete(f"/api/v1/sessions/{sessao_b}", headers=_h(a)).status_code == 204
    assert client.get("/api/v1/sessions", headers=_h(b)).status_code == 401
    restantes = client.get("/api/v1/sessions", headers=_h(a)).json()
    assert [s["id"] for s in restantes] == [decode_access_token(a)["session_id"]]


def test_encerrar_a_propria_sessao_derruba_o_token_atual(client, email):
    a = _login(client, email)
    resposta = client.delete(f"/api/v1/sessions/{decode_access_token(a)['session_id']}", headers=_h(a))
    assert resposta.status_code == 204
    assert client.get("/api/v1/sessions", headers=_h(a)).status_code == 401


def test_nao_encerra_sessao_de_outro_usuario(client, email):
    meu = _login(client, email)
    outro_email = f"ses-{uuid.uuid4().hex[:10]}@teste.dev"
    client.post("/api/v1/auth/register", json={"name": "Bia", "email": outro_email, "password": SENHA})
    alheio = _login(client, outro_email)
    resposta = client.delete(f"/api/v1/sessions/{decode_access_token(alheio)['session_id']}", headers=_h(meu))
    assert resposta.status_code == 404
    assert resposta.json()["code"] == "RES_001"
    assert client.get("/api/v1/sessions", headers=_h(alheio)).status_code == 200


def test_sair_de_todos_os_dispositivos(client, email):
    tokens = [_login(client, email) for _ in range(3)]
    resposta = client.delete("/api/v1/sessions", headers=_h(tokens[0]))
    assert resposta.status_code == 204
    cookie = next(v for k, v in resposta.headers.multi_items() if k == "set-cookie").lower()
    assert "max-age=0" in cookie
    for token in tokens:
        assert client.get("/api/v1/sessions", headers=_h(token)).status_code == 401


def test_rotas_de_sessao_exigem_autenticacao(client):
    assert client.get("/api/v1/sessions").status_code == 401
    assert client.delete("/api/v1/sessions").status_code == 401
    assert client.delete(f"/api/v1/sessions/{uuid.uuid4()}").status_code == 401
