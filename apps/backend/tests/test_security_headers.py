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


def test_referrer_policy(responses):
    assert_everywhere(responses, "referrer-policy", "strict-origin-when-cross-origin")


def test_permissions_policy(responses):
    assert_everywhere(responses, "permissions-policy", "camera=(), microphone=(), geolocation=()")


def test_x_xss_protection(responses):
    assert_everywhere(responses, "x-xss-protection", "0")


def test_cache_control_no_store(responses):
    assert_everywhere(responses, "cache-control", "no-store")


def test_cache_control_nas_rotas_autenticadas_e_de_auth():
    rotas = [
        ("GET", "/api/v1/auth/me"),
        ("GET", "/api/v1/sessions"),
        ("GET", "/api/v1/security/events"),
        ("POST", "/api/v1/auth/refresh"),
        ("POST", "/api/v1/auth/logout"),
    ]
    for method, path in rotas:
        response = client.request(method, path)
        assert response.headers["cache-control"] == "no-store", path


def test_resposta_binaria_de_pdf_tambem_recebe_os_headers():
    # REQ-40/43: o download do PDF assinado precisa de nosniff e no-store.
    from starlette.applications import Starlette
    from starlette.responses import Response
    from starlette.routing import Route

    from app.middlewares.security_headers import SecurityHeadersMiddleware

    def pdf(_request):
        return Response(b"%PDF-1.7\n", media_type="application/pdf")

    pdf_app = Starlette(routes=[Route("/pdf", pdf)])
    pdf_app.add_middleware(SecurityHeadersMiddleware)
    response = TestClient(pdf_app).get("/pdf")
    assert response.headers["content-type"] == "application/pdf"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
