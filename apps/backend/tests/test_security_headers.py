"""Cabeçalhos de segurança HTTP (REQ-37 a 44).

Cada header é conferido numa amostra de respostas bem diferentes: rota
pública, rota autenticada sem token, erro de validação, rota inexistente,
método não permitido e preflights de CORS aceita e recusada.
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.middlewares.security_headers import SECURITY_HEADERS

client = TestClient(app)
ORIGIN = "http://localhost:3039"


def _responses():
    return {
        "publica": client.get("/api/v1/health"),
        "autenticada_sem_token": client.get("/api/v1/auth/me"),
        "validacao": client.post("/api/v1/auth/login", json={}),
        "inexistente": client.get("/api/v1/nao-existe"),
        "metodo_nao_permitido": client.put("/api/v1/health"),
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


def test_erro_500_tambem_recebe_headers_de_seguranca_cors_e_request_id():
    from fastapi import APIRouter

    from app.main import create_app
    from app.middlewares.security_headers import SECURITY_HEADERS

    router = APIRouter()

    @router.get("/_teste/explode")
    def explode():
        raise RuntimeError("detalhe interno que não pode vazar")

    boom_app = create_app()
    boom_app.include_router(router)
    response = TestClient(boom_app).get("/_teste/explode", headers={"Origin": ORIGIN})
    assert response.status_code == 500
    assert response.json()["code"] == "SYS_001"
    assert "detalhe interno" not in response.text
    for name, value in SECURITY_HEADERS.items():
        assert response.headers[name] == value, name
    assert response.headers["access-control-allow-origin"] == ORIGIN
    assert response.json()["request_id"] == response.headers["x-request-id"]


# --------------------------------------------------------------- QA caixa-branca


def _qa_client():
    """App real com rotas que já trazem headers próprios, fazem streaming ou quebram."""
    from fastapi import APIRouter
    from fastapi.responses import JSONResponse, StreamingResponse

    from app.main import create_app

    router = APIRouter()

    @router.get("/_qa/route-headers")
    def route_headers():
        return JSONResponse(
            {},
            headers={
                "Cache-Control": "public, max-age=60",
                "X-Frame-Options": "SAMEORIGIN",
                "Content-Security-Policy": "sandbox",
            },
        )

    @router.get("/_qa/pdf-stream")
    def pdf_stream():
        return StreamingResponse(iter([b"%PDF-1.7\n", b"..."]), media_type="application/pdf")

    @router.get("/_qa/stream-boom")
    def stream_boom():
        def gen():
            yield b"%PDF-"
            raise RuntimeError("falha no meio do stream")

        return StreamingResponse(gen(), media_type="application/pdf")

    @router.get("/_qa/boom")
    def boom():
        raise RuntimeError("detalhe interno")

    qa_app = create_app()
    qa_app.include_router(router)
    return qa_app


qa_app = _qa_client()
qa_client = TestClient(qa_app)


def test_headers_de_seguranca_sobrescrevem_a_rota_sem_duplicar():
    # Decisão de projeto: os valores do REQ-37..44 são fixos. Uma rota não consegue
    # enfraquecê-los (nem trocar por outro valor), e nenhum header sai duplicado.
    response = qa_client.get("/_qa/route-headers")
    for name, value in SECURITY_HEADERS.items():
        assert response.headers.get_list(name) == [value], name


def test_pdf_em_streaming_recebe_nosniff_no_store_e_cors():
    # REQ-40/43 na app real, com resposta em várias partes (como o download do PDF).
    response = qa_client.get("/_qa/pdf-stream", headers={"Origin": ORIGIN})
    assert response.headers["content-type"] == "application/pdf"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["access-control-allow-origin"] == ORIGIN


def test_erro_depois_do_inicio_da_resposta_propaga_a_excecao_original():
    # Com a resposta já começada não dá para trocar por um 500: a exceção segue adiante.
    with pytest.raises(RuntimeError, match="falha no meio do stream"):
        qa_client.get("/_qa/stream-boom")


def test_erro_500_e_logado_uma_unica_vez_com_request_id(caplog, monkeypatch):
    import logging

    # O fileConfig do alembic/env.py (rodado pelos testes de migration) desliga os loggers
    # que já existiam; aqui o logger precisa estar ativo, como no processo da API.
    monkeypatch.setattr(logging.getLogger("saferdocs.errors"), "disabled", False)
    with caplog.at_level(logging.ERROR, logger="saferdocs.errors"):
        response = qa_client.get("/_qa/boom")
    assert response.status_code == 500
    registros = [r for r in caplog.records if r.name == "saferdocs.errors"]
    assert len(registros) == 1
    assert registros[0].exc_info is not None
    assert response.json()["request_id"] in registros[0].getMessage()


@pytest.mark.parametrize("exc", ["CancelledError", "KeyboardInterrupt"])
def test_base_exception_nao_vira_500(exc):
    # Cancelamento e Ctrl+C não são erros da aplicação: não podem virar resposta 500.
    import asyncio

    from app.middlewares.unhandled_errors import UnhandledErrorMiddleware

    exc_type = asyncio.CancelledError if exc == "CancelledError" else KeyboardInterrupt

    async def inner(scope, receive, send):
        raise exc_type()

    sent = []

    async def send(message):
        sent.append(message)

    async def receive():
        return {"type": "http.request", "body": b""}

    scope = {"type": "http", "method": "GET", "path": "/", "headers": [], "query_string": b""}
    with pytest.raises(exc_type):
        asyncio.run(UnhandledErrorMiddleware(inner)(scope, receive, send))
    assert sent == []
