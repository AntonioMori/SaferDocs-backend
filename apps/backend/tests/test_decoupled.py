"""RNF-01: o backend é só uma API HTTP; o frontend é outra aplicação."""

from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from app.main import app


def test_nao_ha_arquivos_estaticos_nem_rotas_fora_da_api():
    for rota in app.routes:
        nome = type(rota).__name__
        assert nome != "Mount", f"o backend não serve arquivos ({rota})"
        if isinstance(rota, APIRoute):
            assert rota.path.startswith("/api/")


def test_respostas_sao_json_e_nao_html():
    client = TestClient(app)
    for caminho in ("/", "/index.html", "/api/v1/health"):
        resposta = client.get(caminho)
        assert resposta.headers["content-type"].startswith("application/json"), caminho
        assert "<html" not in resposta.text.lower()
