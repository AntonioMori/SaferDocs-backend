"""RNF-12: todos os erros seguem o objeto padronizado."""

import re
from datetime import datetime

import pytest
from fastapi import APIRouter
from fastapi.testclient import TestClient
from pydantic import BaseModel

from app.core.errors import AppError, ErrorCode
from app.main import create_app

router = APIRouter(prefix="/_teste")


class Corpo(BaseModel):
    email: str
    idade: int


@router.get("/app-error")
def _app_error():
    raise AppError(ErrorCode.NOT_FOUND, "Documento não encontrado.")


@router.get("/explode")
def _explode():
    raise RuntimeError("SELECT * FROM users WHERE senha = 'segredo'")


@router.post("/valida")
def _valida(corpo: Corpo):
    return corpo


@pytest.fixture(scope="module")
def client():
    app = create_app()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


def _padrao(resposta) -> dict:
    corpo = resposta.json()
    assert {"code", "message", "timestamp", "request_id"} <= corpo.keys()
    assert re.match(r"^[A-Z]+_\d{3}$", corpo["code"])
    datetime.fromisoformat(corpo["timestamp"].replace("Z", "+00:00"))
    assert corpo["timestamp"].endswith("Z")
    return corpo


def test_app_error_usa_o_formato(client):
    resposta = client.get("/_teste/app-error")
    assert resposta.status_code == 404
    corpo = _padrao(resposta)
    assert corpo["code"] == "RES_001"
    assert corpo["message"] == "Documento não encontrado."


def test_rota_inexistente_usa_o_formato(client):
    resposta = client.get("/api/v1/nao-existe")
    assert resposta.status_code == 404
    assert _padrao(resposta)["code"] == "RES_001"


def test_metodo_nao_permitido_usa_o_formato(client):
    resposta = client.delete("/api/v1/health")
    assert resposta.status_code == 405
    assert _padrao(resposta)["code"] == "RES_002"


def test_erro_inesperado_vira_500_sem_detalhes(client):
    resposta = client.get("/_teste/explode")
    assert resposta.status_code == 500
    corpo = _padrao(resposta)
    assert corpo["code"] == "SYS_001"
    assert "SELECT" not in resposta.text
    assert "Traceback" not in resposta.text


def test_validacao_usa_o_formato_com_campos(client):
    resposta = client.post("/_teste/valida", json={"email": "a@b.c", "idade": "x"})
    assert resposta.status_code == 400
    corpo = _padrao(resposta)
    assert corpo["code"] == "VAL_001"
    assert corpo["fields"][0]["field"] == "idade"


def test_request_id_do_cliente_e_devolvido(client):
    resposta = client.get("/api/v1/nao-existe", headers={"X-Request-ID": "abc-123"})
    assert resposta.headers["x-request-id"] == "abc-123"
    assert resposta.json()["request_id"] == "abc-123"


def test_request_id_inseguro_e_substituido(client):
    resposta = client.get("/api/v1/nao-existe", headers={"X-Request-ID": "<script>"})
    assert resposta.headers["x-request-id"] != "<script>"
    assert re.match(r"^[0-9a-f-]{36}$", resposta.json()["request_id"])
