"""Cabeçalhos de segurança HTTP (REQ-37 a 44).

Cada header é conferido numa amostra de respostas bem diferentes: rota
pública, rota autenticada sem token, erro de validação, rota inexistente,
método não permitido e preflights de CORS aceita e recusada.
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)
ORIGIN = "http://localhost:3039"


def _responses():
    return {
        "publica": client.get("/api/v1/health"),
        "autenticada_sem_token": client.get("/api/v1/auth/me"),
        "validacao": client.post("/api/v1/auth/login", json={}),
        "inexistente": client.get("/api/v1/nao-existe"),
        "metodo_nao_permitido": client.head("/api/v1/health"),
        "preflight_aceita": client.options(
            "/api/v1/sessions", headers={"Origin": ORIGIN, "Access-Control-Request-Method": "DELETE"}
        ),
        "preflight_recusada": client.options(
            "/api/v1/sessions",
            headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
        ),
    }


@pytest.fixture(scope="module")
def responses():
    return _responses()


def assert_everywhere(responses, header: str, value: str) -> None:
    for name, response in responses.items():
        assert response.headers.get(header) == value, f"{header} ausente ou errado em: {name}"


def test_amostra_cobre_os_casos_esperados(responses):
    status = {name: r.status_code for name, r in responses.items()}
    assert status == {
        "publica": 200,
        "autenticada_sem_token": 401,
        "validacao": 400,
        "inexistente": 404,
        "metodo_nao_permitido": 405,
        "preflight_aceita": 204,
        "preflight_recusada": 403,
    }


def test_content_security_policy(responses):
    assert_everywhere(
        responses,
        "content-security-policy",
        "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'",
    )


def test_strict_transport_security(responses):
    assert_everywhere(responses, "strict-transport-security", "max-age=63072000; includeSubDomains; preload")


def test_x_frame_options(responses):
    assert_everywhere(responses, "x-frame-options", "DENY")


def test_x_content_type_options(responses):
    assert_everywhere(responses, "x-content-type-options", "nosniff")
