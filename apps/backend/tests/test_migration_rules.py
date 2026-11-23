"""RNF-11: identificação das migrations e regras de trabalho em paralelo."""

import ast
import re
from pathlib import Path

import pytest
from alembic.script import ScriptDirectory

from tests.conftest import alembic_config

VERSIONS = Path(__file__).resolve().parent.parent / "alembic" / "versions"
NAME_PATTERN = re.compile(r"^\d{8}_\d{4}_[0-9a-f]+_[a-z0-9_]+\.py$")
MIGRATIONS = sorted(p for p in VERSIONS.glob("*.py") if p.name != "__init__.py")


def test_existe_ao_menos_uma_migration():
    assert MIGRATIONS


@pytest.mark.parametrize("arquivo", MIGRATIONS, ids=lambda p: p.name)
def test_nome_comeca_com_data_e_hora(arquivo):
    assert NAME_PATTERN.match(arquivo.name), (
        "use: alembic revision -m '...' (o nome é gerado com data e hora)"
    )


@pytest.mark.parametrize("arquivo", MIGRATIONS, ids=lambda p: p.name)
def test_tem_upgrade_e_downgrade_implementados(arquivo):
    arvore = ast.parse(arquivo.read_text(encoding="utf-8"))
    funcoes = {n.name: n for n in arvore.body if isinstance(n, ast.FunctionDef)}
    for nome in ("upgrade", "downgrade"):
        assert nome in funcoes, f"{arquivo.name} não define {nome}()"
        corpo = [
            n
            for n in funcoes[nome].body
            if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant))  # ignora docstring
        ]
        assert corpo and not all(isinstance(n, ast.Pass) for n in corpo), (
            f"{nome}() está vazio em {arquivo.name}"
        )


def test_historico_tem_uma_unica_cabeca():
    cabecas = ScriptDirectory.from_config(alembic_config()).get_heads()
    assert len(cabecas) == 1, (
        f"Há {len(cabecas)} cabeças ({cabecas}). Duas migrations foram criadas em paralelo: "
        "rode `uv run alembic merge heads -m 'merge'`."
    )
