"""Proteção contra CSRF por Origin/Referer (REQ-65)."""

import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app

FRONT = "http://localhost:3039"
SENHA = "Senha-Forte#2026"


@pytest.fixture
def client(migrated_db):
    return TestClient(app)


@pytest.fixture
def logado(client):
    """Cliente com o cookie de refresh de uma sessão real, como o navegador do usuário.

    O cookie tem a flag Secure e o TestClient usa http: o valor é recolocado à mão,
    como nos testes do refresh.
    """
    from app.services.token_service import REFRESH_COOKIE_NAME

    email = f"csrf-{uuid.uuid4().hex[:10]}@teste.dev"
    client.post("/api/v1/auth/register", json={"name": "Ana", "email": email, "password": SENHA})
    resposta = client.post(
        "/api/v1/auth/login", json={"email": email, "password": SENHA}, headers={"Origin": FRONT}
    )
    assert resposta.status_code == 200
    valor = next(
        v.split(";")[0].split("=", 1)[1].strip('"')
        for k, v in resposta.headers.multi_items()
        if k == "set-cookie" and v.startswith(f"{REFRESH_COOKIE_NAME}=")
    )
    client.cookies.clear()
    client.cookies.set(REFRESH_COOKIE_NAME, valor, path="/api/v1/auth")
    return client


def test_post_com_origin_de_outro_site_recebe_403(logado):
    # Critério de aceite: POST com Origin de outro site retorna 403 AUTH_009.
    for rota in ("/api/v1/auth/refresh", "/api/v1/auth/logout"):
        resposta = logado.post(rota, headers={"Origin": "https://evil.example"})
        assert resposta.status_code == 403
        assert resposta.json()["code"] == "AUTH_009"


def test_refresh_com_origin_do_front_funciona(logado):
    resposta = logado.post("/api/v1/auth/refresh", headers={"Origin": FRONT})
    assert resposta.status_code == 200
    assert resposta.json()["access_token"]


def test_ataque_nao_gasta_o_refresh_token(logado):
    # A requisição forjada é barrada antes da rota: o refresh legítimo continua valendo.
    logado.post("/api/v1/auth/refresh", headers={"Origin": "https://evil.example"})
    assert logado.post("/api/v1/auth/refresh", headers={"Origin": FRONT}).status_code == 200


@pytest.mark.parametrize(
    "headers",
    [
        {"Origin": "null"},  # iframe sandbox, data: URL
        {"Origin": "http://localhost:3039.evil.example"},
        {"Origin": "https://localhost:3039"},
        {"Referer": "https://evil.example/pagina"},
        {"Referer": "http://localhost:3039.evil.example/"},
        {},  # cookie sem nenhuma origem verificável
    ],
    ids=["null", "subdominio-falso", "outro-esquema", "referer-de-fora", "referer-parecido", "sem-origem"],
)
def test_pedido_com_cookie_e_origem_invalida_ou_ausente_e_recusado(logado, headers):
    resposta = logado.post("/api/v1/auth/logout", headers=headers)
    assert resposta.status_code == 403
    assert resposta.json()["code"] == "AUTH_009"


def test_referer_do_front_vale_sem_origin(logado):
    resposta = logado.post("/api/v1/auth/refresh", headers={"Referer": f"{FRONT}/conta/seguranca?x=1"})
    assert resposta.status_code == 200


def test_origin_repetido_e_recusado(logado):
    resposta = logado.post(
        "/api/v1/auth/refresh", headers=[("Origin", FRONT), ("Origin", "https://evil.example")]
    )
    assert resposta.status_code == 403


def test_cliente_de_api_sem_cookie_e_sem_origin_passa(client):
    # curl ou outro serviço usando só o Bearer: não é alvo de CSRF.
    resposta = client.post("/api/v1/auth/login", json={"email": "x@teste.dev", "password": "y"})
    assert resposta.status_code == 401  # chegou na rota (credencial inválida), não 403


def test_metodos_que_nao_alteram_estado_nao_sao_barrados(logado):
    assert logado.get("/api/v1/health", headers={"Origin": "https://evil.example"}).status_code == 200


@pytest.mark.parametrize("metodo", ["PUT", "DELETE", "PATCH"])
def test_todos_os_metodos_que_alteram_estado_sao_conferidos(logado, metodo):
    resposta = logado.request(metodo, "/api/v1/sessions", headers={"Origin": "https://evil.example"})
    assert resposta.status_code == 403


def test_formulario_html_de_outro_site_e_barrado(logado):
    # O ataque clássico: <form method=post action=".../auth/logout"> num site malicioso.
    resposta = logado.post(
        "/api/v1/auth/logout",
        content="a=1",
        headers={"Origin": "https://evil.example", "Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resposta.status_code == 403


def test_403_do_csrf_tem_headers_de_seguranca_e_request_id(logado):
    resposta = logado.post("/api/v1/auth/logout", headers={"Origin": "https://evil.example"})
    assert resposta.headers["x-frame-options"] == "DENY"
    assert resposta.json()["request_id"] == resposta.headers["x-request-id"]
