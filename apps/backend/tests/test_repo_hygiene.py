"""RNF-07: nenhum .env nem chave privada é versionado."""

import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]


def _git(*args: str) -> str:
    git = shutil.which("git")
    if git is None or not (REPO / ".git").exists():
        pytest.skip("fora de um clone git")
    return subprocess.run([git, *args], cwd=REPO, capture_output=True, text=True, check=True).stdout  # noqa: S603


def test_nenhum_env_ou_chave_versionado():
    arquivos = _git("ls-files").splitlines()
    proibidos = [
        f
        for f in arquivos
        if (Path(f).name.startswith(".env") and Path(f).name != ".env.example")
        or f.endswith((".pem", ".key"))
    ]
    assert proibidos == []


def test_env_esta_no_gitignore():
    saida = _git("check-ignore", "apps/backend/.env", "apps/backend/.env.production", "chave.pem")
    assert len(saida.splitlines()) == 3


def test_env_example_nao_e_ignorado():
    resultado = subprocess.run(  # noqa: S603
        [shutil.which("git") or "git", "check-ignore", "-q", "apps/backend/.env.example"], cwd=REPO
    )
    assert resultado.returncode == 1
