"""RNF-13: códigos de erro consistentes por domínio, num catálogo único."""

import re
from pathlib import Path

from app.core.errors import CATALOG, ErrorCode

DOMINIOS = {"AUTH", "DOC", "VAL", "RES", "RATE", "SYS"}
APP_DIR = Path(__file__).resolve().parent.parent / "app"
CODIGO = re.compile(r"\b(?:AUTH|DOC|VAL|RES|RATE|SYS)_\d{3}\b")


def test_todo_codigo_segue_o_padrao_dominio_numero():
    for code in ErrorCode:
        assert re.fullmatch(r"[A-Z]+_\d{3}", code.value), code
        assert code.domain in DOMINIOS, code


def test_nome_do_membro_corresponde_ao_dominio():
    prefixos = {"AUTH": "AUTH_", "DOC": "DOC_"}
    for code in ErrorCode:
        if code.domain in prefixos:
            assert code.name.startswith(prefixos[code.domain]), code.name


def test_codigos_sao_unicos():
    valores = [c.value for c in ErrorCode]
    assert len(valores) == len(set(valores))


def test_todo_codigo_tem_status_e_mensagem():
    assert set(CATALOG) == set(ErrorCode)
    for spec in CATALOG.values():
        assert 400 <= spec.status <= 599
        assert spec.message


def test_nenhum_codigo_escrito_fora_do_catalogo():
    fora = []
    for arquivo in APP_DIR.rglob("*.py"):
        if arquivo.name == "errors.py" and arquivo.parent.name == "core":
            continue
        for numero, linha in enumerate(arquivo.read_text(encoding="utf-8").splitlines(), 1):
            if CODIGO.search(linha):
                fora.append(f"{arquivo.relative_to(APP_DIR)}:{numero}")
    assert fora == [], f"Use ErrorCode em vez de escrever o código: {fora}"
