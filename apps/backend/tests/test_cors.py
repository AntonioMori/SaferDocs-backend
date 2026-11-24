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
