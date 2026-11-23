"""RNF-14: erros de validação listam campos e motivos, sem detalhes internos."""

import pytest
from fastapi import APIRouter
from fastapi.testclient import TestClient
from pydantic import BaseModel, Field, field_validator

from app.main import create_app

router = APIRouter(prefix="/_teste")


class Cadastro(BaseModel):
    nome: str = Field(min_length=2, max_length=10)
    idade: int = Field(gt=0)
    apelido: str

    @field_validator("apelido")
    @classmethod
    def _sem_espacos(cls, valor: str) -> str:
        if " " in valor:
            raise ValueError("não pode conter espaços")
        return valor


@router.post("/cadastro")
def _cadastro(dados: Cadastro):
    return dados


@pytest.fixture(scope="module")
def client():
    app = create_app()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=False)


def _campos(resposta) -> dict[str, str]:
    assert resposta.status_code == 400
    corpo = resposta.json()
    assert corpo["code"] == "VAL_001"
    return {f["field"]: f["reason"] for f in corpo["fields"]}


def test_lista_todos_os_campos_invalidos_com_motivo(client):
    campos = _campos(client.post("/_teste/cadastro", json={"nome": "a", "idade": 0, "apelido": "x y"}))
    assert campos == {
        "nome": "mínimo de 2 caracteres",
        "idade": "deve ser > 0",
        "apelido": "não pode conter espaços",
    }


def test_campo_ausente_e_tipo_errado(client):
    campos = _campos(client.post("/_teste/cadastro", json={"nome": "Ana", "idade": "dez"}))
    assert campos == {"idade": "deve ser um número inteiro", "apelido": "campo obrigatório"}


def test_json_malformado(client):
    resposta = client.post(
        "/_teste/cadastro", content=b'{"nome": ', headers={"Content-Type": "application/json"}
    )
    assert "JSON inválido" in _campos(resposta).values()


def test_resposta_nao_ecoa_o_valor_enviado_nem_detalhes_internos(client):
    ataque = "<script>alert(1)</script>"
    resposta = client.post("/_teste/cadastro", json={"nome": ataque, "idade": "' OR 1=1 --", "apelido": "ok"})
    texto = resposta.text
    assert ataque not in texto
    assert "OR 1=1" not in texto
    for interno in ("pydantic", "Traceback", "input", "url", "ctx", "loc"):
        assert interno not in texto
