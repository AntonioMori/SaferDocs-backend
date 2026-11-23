"""RNF-16: todos os endpoints ficam sob o prefixo /api/v1/."""

from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from app.main import app

PREFIXO = "/api/v1/"


def test_toda_rota_esta_sob_api_v1():
    fora = [r.path for r in app.routes if isinstance(r, APIRoute) and not r.path.startswith(PREFIXO)]
    assert fora == []


def test_openapi_tambem_esta_sob_api_v1():
    assert app.openapi_url is None or app.openapi_url.startswith(PREFIXO)


def test_sem_prefixo_retorna_404():
    assert TestClient(app).get("/health").status_code == 404
    assert TestClient(app).get("/api/v1/health").status_code == 200
