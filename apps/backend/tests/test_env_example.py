"""RNF-06: o .env.example documenta todas as variáveis lidas pelo Settings."""

import re
from pathlib import Path

from app.core.config import Settings

EXAMPLE = Path(__file__).resolve().parent.parent / ".env.example"
SECRETS = (
    "POSTGRES_PASSWORD",
    "JWT_PRIVATE_KEY_PEM_B64",
    "JWT_PUBLIC_KEY_PEM_B64",
    "MASTER_KEY",
    "HASH_PEPPER",
)


def _example_vars() -> dict[str, str]:
    pairs = re.findall(r"^([A-Z0-9_]+)=(.*)$", EXAMPLE.read_text(encoding="utf-8"), flags=re.MULTILINE)
    return dict(pairs)


def test_toda_variavel_do_settings_esta_no_example():
    documentadas = set(_example_vars())
    esperadas = {name.upper() for name in Settings.model_fields}
    assert esperadas - documentadas == set()


def test_example_nao_tem_segredos_preenchidos():
    variaveis = _example_vars()
    for nome in SECRETS:
        assert variaveis[nome] == "", f"{nome} deveria estar vazio no .env.example"
