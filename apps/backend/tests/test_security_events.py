"""REQ-58: atividade de segurança da conta, com eventos não vistos destacados no próximo login."""

import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app

SENHA = "Senha-Forte#2026"
NOVA = "Outra-Senha#2027"
IP_CASA = "203.0.113.20"
IP_VIAGEM = "198.51.100.30"


def _cliente(ip: str = IP_CASA) -> TestClient:
    return TestClient(app, client=(ip, 5000))


def _login(ip: str, email: str, senha: str = SENHA) -> dict:
    resposta = _cliente(ip).post("/api/v1/auth/login", json={"email": email, "password": senha})
    assert resposta.status_code == 200
    return resposta.json()


def _h(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _eventos(token: str, ip: str = IP_CASA) -> list[dict]:
    resposta = _cliente(ip).get("/api/v1/security/events", headers=_h(token))
    assert resposta.status_code == 200
    return resposta.json()


@pytest.fixture
def email(migrated_db) -> str:
    email = f"sec-{uuid.uuid4().hex[:10]}@teste.dev"
    resposta = _cliente(IP_CASA).post(
        "/api/v1/auth/register", json={"name": "Ana", "email": email, "password": SENHA}
    )
    assert resposta.status_code == 201
    return email


# ------------------------------------------------------------------ IP desconhecido


def test_login_do_ip_do_cadastro_nao_gera_alerta(email):
    corpo = _login(IP_CASA, email)
    assert corpo["unseen_security_events"] == 0
    assert _eventos(corpo["access_token"]) == []


def test_login_de_ip_desconhecido_gera_evento_nao_visto(email):
    corpo = _login(IP_VIAGEM, email)
    eventos = _eventos(corpo["access_token"], IP_VIAGEM)
    assert [(e["type"], e["seen"]) for e in eventos] == [("NEW_IP_LOGIN", False)]
    assert eventos[0]["details"]["ip"] == IP_VIAGEM


def test_ip_ja_usado_nao_alerta_de_novo(email):
    _login(IP_VIAGEM, email)
    token = _login(IP_VIAGEM, email)["access_token"]
    assert [e["type"] for e in _eventos(token, IP_VIAGEM)] == ["NEW_IP_LOGIN"]


# ------------------------------------------------------------------ destaque no próximo login


def test_evento_novo_aparece_como_nao_visto_no_login_seguinte(email):
    token = _login(IP_CASA, email)["access_token"]
    assert (
        _cliente()
        .put(
            "/api/v1/auth/password", json={"current_password": SENHA, "new_password": NOVA}, headers=_h(token)
        )
        .status_code
        == 200
    )

    corpo = _login(IP_CASA, email, NOVA)
    assert corpo["unseen_security_events"] == 1
    assert [(e["type"], e["seen"]) for e in _eventos(corpo["access_token"])] == [("PASSWORD_CHANGED", False)]


def test_marcar_como_visto_tira_o_destaque(email):
    _login(IP_VIAGEM, email)
    token = _login(IP_CASA, email)["access_token"]
    ids = [e["id"] for e in _eventos(token)]

    assert (
        _cliente().post("/api/v1/security/events/seen", json={"ids": ids}, headers=_h(token)).status_code
        == 204
    )
    assert all(e["seen"] for e in _eventos(token))
    assert _login(IP_CASA, email)["unseen_security_events"] == 0


def test_nao_vistos_vem_primeiro(email):
    _login(IP_VIAGEM, email)
    token = _login(IP_CASA, email)["access_token"]
    visto = _eventos(token)[0]["id"]
    _cliente().post("/api/v1/security/events/seen", json={"ids": [visto]}, headers=_h(token))
    _login("192.0.2.40", email)  # novo evento, ainda não visto
    assert [e["seen"] for e in _eventos(token)] == [False, True]


# ------------------------------------------------------------------ isolamento entre contas


def test_nao_marca_evento_de_outro_usuario(email, migrated_db):
    alheio = _login(IP_VIAGEM, email)["access_token"]
    evento_alheio = _eventos(alheio, IP_VIAGEM)[0]["id"]

    outro = f"sec-{uuid.uuid4().hex[:10]}@teste.dev"
    _cliente().post("/api/v1/auth/register", json={"name": "Bia", "email": outro, "password": SENHA})
    meu = _login(IP_CASA, outro)["access_token"]

    assert _eventos(meu) == []
    resposta = _cliente().post("/api/v1/security/events/seen", json={"ids": [evento_alheio]}, headers=_h(meu))
    assert resposta.status_code == 204
    assert _eventos(alheio, IP_VIAGEM)[0]["seen"] is False


def test_lista_de_ids_vazia_e_recusada(email):
    token = _login(IP_CASA, email)["access_token"]
    resposta = _cliente().post("/api/v1/security/events/seen", json={"ids": []}, headers=_h(token))
    assert resposta.status_code == 400
    assert resposta.json()["code"] == "VAL_001"


@pytest.mark.parametrize(("metodo", "rota"), [("GET", "/events"), ("POST", "/events/seen")])
def test_rotas_exigem_autenticacao(migrated_db, metodo, rota):
    resposta = _cliente().request(metodo, f"/api/v1/security{rota}", json={"ids": [str(uuid.uuid4())]})
    assert resposta.status_code == 401
