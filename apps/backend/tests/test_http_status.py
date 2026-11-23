"""RNF-15: códigos de status HTTP usados corretamente."""

import re
from pathlib import Path

import pytest
from fastapi import APIRouter
from fastapi.testclient import TestClient

from app.core.errors import CATALOG, AppError, ErrorCode
from app.main import create_app

README = Path(__file__).resolve().parent.parent / "README.md"

# Semântica de cada status (tabela do RNF-15 + os específicos do projeto).
ESPERADO = {
    401: {"AUTH_001", "AUTH_002", "AUTH_003", "AUTH_004", "AUTH_005"},  # não autenticado
    403: {"AUTH_009", "AUTH_010"},  # autenticado/identificado, mas sem permissão
    404: {"RES_001"},
    405: {"RES_002"},
    413: {"DOC_002"},
    429: {"RATE_001"},
    500: {"SYS_001"},
}


def test_status_por_codigo():
    for status, codigos in ESPERADO.items():
        for codigo in codigos:
            assert CATALOG[ErrorCode(codigo)].status == status, codigo


def test_demais_codigos_sao_erros_do_cliente_400():
    especiais = set().union(*ESPERADO.values())
    for code, spec in CATALOG.items():
        if code.value not in especiais:
            assert spec.status == 400, code


@pytest.mark.parametrize("code", list(ErrorCode), ids=lambda c: c.value)
def test_resposta_http_usa_o_status_do_catalogo(code):
    router = APIRouter()

    @router.get("/_teste/erro")
    def _erro():
        raise AppError(code)

    app = create_app()
    app.include_router(router)
    resposta = TestClient(app).get("/_teste/erro")
    assert resposta.status_code == CATALOG[code].status
    assert resposta.json()["code"] == code.value


def test_tabela_do_readme_esta_sincronizada_com_o_catalogo():
    texto = README.read_text(encoding="utf-8")
    bloco = texto.split("<!-- tabela-de-erros:inicio -->")[1].split("<!-- tabela-de-erros:fim -->")[0]
    linhas = re.findall(r"^\| `([A-Z]+_\d{3})` \| (\d{3}) \| (.+?) \|$", bloco, flags=re.MULTILINE)
    no_readme = {codigo: (int(status), msg) for codigo, status, msg in linhas}
    no_catalogo = {c.value: (s.status, s.message) for c, s in CATALOG.items()}
    assert no_readme == no_catalogo, "Atualize a tabela de erros do README"
