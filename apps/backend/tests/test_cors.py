"""CORS (REQ-31 a 36)."""

from fastapi.testclient import TestClient

from app.main import app

ALLOWED = "http://localhost:3039"  # CORS_ALLOWED_ORIGINS do conftest
FOREIGN = "https://evil.example"

client = TestClient(app)


def test_origem_permitida_recebe_a_propria_origem():
    response = client.get("/api/v1/health", headers={"Origin": ALLOWED})
    assert response.headers["access-control-allow-origin"] == ALLOWED
    assert "Origin" in response.headers["vary"]


def test_origem_fora_da_lista_nao_recebe_allow_origin():
    response = client.get("/api/v1/health", headers={"Origin": FOREIGN})
    assert "access-control-allow-origin" not in response.headers
    assert "Origin" in response.headers["vary"]


def test_nunca_responde_com_asterisco():
    for origin in (ALLOWED, FOREIGN, "null"):
        response = client.get("/api/v1/health", headers={"Origin": origin})
        assert response.headers.get("access-control-allow-origin") != "*"


def test_origem_parecida_nao_e_aceita():
    for origin in (
        ALLOWED + ".evil.example",
        ALLOWED + "/",
        "http://localhost:3040",
        "https://localhost:3039",
    ):
        response = client.get("/api/v1/health", headers={"Origin": origin})
        assert "access-control-allow-origin" not in response.headers


def test_sem_origin_nao_adiciona_headers_cors():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers


# --------------------------------------------------------------- preflight (REQ-35)


def preflight(path: str = "/api/v1/auth/password", *, origin: str = ALLOWED, method: str = "PUT", headers=""):
    request_headers = {"Origin": origin, "Access-Control-Request-Method": method}
    if headers:
        request_headers["Access-Control-Request-Headers"] = headers
    return client.options(path, headers=request_headers)


def test_preflight_put_com_authorization_retorna_os_headers_certos():
    response = preflight(method="PUT", headers="authorization, content-type")
    assert response.status_code == 204
    assert response.headers["access-control-allow-origin"] == ALLOWED
    assert response.headers["access-control-allow-methods"] == "GET, POST, PUT, DELETE, OPTIONS"
    assert response.headers["access-control-allow-headers"] == "Authorization, Content-Type, X-Request-ID"
    assert "Origin" in response.headers["vary"]
    assert response.content == b""


def test_preflight_responde_antes_da_autenticacao():
    # Rota autenticada, sem token: a preflight não chega ao get_current_user.
    response = preflight("/api/v1/sessions", method="DELETE", headers="authorization")
    assert response.status_code == 204


def test_preflight_responde_em_qualquer_rota_da_api():
    assert preflight("/api/v1/rota-que-nao-existe", method="GET").status_code == 204


def test_preflight_de_origem_fora_da_lista_e_recusada():
    response = preflight(origin=FOREIGN, headers="authorization")
    assert response.status_code == 403
    assert response.json()["code"] == "AUTH_009"
    assert response.json()["request_id"] == response.headers["x-request-id"]
    assert "access-control-allow-origin" not in response.headers
    assert "access-control-allow-methods" not in response.headers


# --------------------------------------------------------------- métodos (REQ-32)


def test_metodos_permitidos_passam_na_preflight():
    for method in ("GET", "POST", "PUT", "DELETE", "OPTIONS"):
        assert preflight(method=method).status_code == 204, method


def test_patch_e_recusado_na_preflight():
    response = preflight(method="PATCH")
    assert response.status_code == 403
    assert response.json()["code"] == "AUTH_009"
    assert "access-control-allow-origin" not in response.headers
    assert "access-control-allow-methods" not in response.headers


def test_outros_metodos_sao_recusados_na_preflight():
    for method in ("HEAD", "TRACE", "CONNECT", "PROPFIND", "put", ""):
        assert preflight(method=method).status_code == 403, method


# --------------------------------------------------------------- headers (REQ-33)


def test_headers_permitidos_passam_em_qualquer_caixa():
    for headers in (
        "authorization",
        "Content-Type",
        "x-request-id",
        "AUTHORIZATION, content-type, X-Request-Id",
    ):
        assert preflight(headers=headers).status_code == 204, headers


def test_header_customizado_e_recusado_na_preflight():
    response = preflight(headers="authorization, x-csrf-token")
    assert response.status_code == 403
    assert response.json()["code"] == "AUTH_009"
    assert "access-control-allow-origin" not in response.headers
    assert "access-control-allow-headers" not in response.headers


def test_outros_headers_sao_recusados_na_preflight():
    for headers in ("cookie", "x-forwarded-for", "x-api-key", "authorization,,x-debug"):
        assert preflight(headers=headers).status_code == 403, headers


def test_lista_de_headers_vazia_ou_com_virgulas_sobrando_passa():
    assert preflight(headers=" , authorization ,").status_code == 204


def test_options_sem_request_method_nao_e_preflight():
    # Sem Access-Control-Request-Method, é um OPTIONS comum e vai para as rotas.
    response = client.options("/api/v1/health", headers={"Origin": ALLOWED})
    assert response.status_code == 405
    assert response.headers["access-control-allow-origin"] == ALLOWED
