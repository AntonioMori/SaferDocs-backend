"""Entradas de texto sanitizadas (REQ-64): XSS e injeção de SQL."""

import ast
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect, select

from app.core.text_input import clean_text
from app.db.models import User
from app.db.session import get_engine, get_sessionmaker
from app.main import app

SENHA = "Senha-Forte#2026"
APP_DIR = Path(__file__).resolve().parent.parent / "app"


@pytest.fixture
def client(migrated_db):
    return TestClient(app)


def _cadastrar(client, nome: str, email: str | None = None):
    email = email or f"txt-{uuid.uuid4().hex[:10]}@teste.dev"
    return client.post("/api/v1/auth/register", json={"name": nome, "email": email, "password": SENHA})


# --------------------------------------------------------------- XSS: recusado


@pytest.mark.parametrize(
    "nome",
    [
        "<script>alert(1)</script>",
        "Ana <img src=x onerror=alert(1)>",
        "Ana\x00Souza",  # byte nulo
        "Ana\nSouza",  # quebra de linha (cabeçalhos, logs, selo)
        "Ana‮azuoS",  # inversão de direção do texto
        "Ana​Souza",  # espaço de largura zero
        "Ana﻿Souza",  # BOM no meio
        "﹤script﹥",  # "<" e ">" de largura reduzida: o NFKC transforma em < e >
    ],
    ids=["script", "img", "nulo", "quebra", "bidi", "zero-width", "bom", "menor-maior-unicode"],
)
def test_nome_com_conteudo_malicioso_e_recusado(client, nome):
    # Critério de aceite: entradas maliciosas são recusadas.
    resposta = _cadastrar(client, nome)
    assert resposta.status_code == 400
    corpo = resposta.json()
    assert corpo["code"] == "VAL_001"
    assert corpo["fields"][0]["field"] == "name"
    assert "<script" not in resposta.text and "onerror" not in resposta.text  # erro não reflete a entrada


def test_email_com_html_e_recusado(client):
    resposta = _cadastrar(client, "Ana", email="<script>@teste.dev")
    assert resposta.status_code == 400
    assert resposta.json()["fields"][0]["field"] == "email"


# --------------------------------------------------------------- neutralizado: aceito e gravado como texto


def test_nome_normalizado_nfkc_e_espacos(client):
    resposta = _cadastrar(client, "  ＡＮＡ      Souza  ")  # letras de largura cheia, espaços sobrando
    assert resposta.status_code == 201
    assert resposta.json()["name"] == "ANA Souza"


def test_tentativa_de_sql_injection_no_nome_vira_texto_comum(client):
    nome = "Robert'); DROP TABLE users;--"
    resposta = _cadastrar(client, nome)
    assert resposta.status_code == 201
    with get_sessionmaker()() as db:
        assert db.scalar(select(User.name).where(User.id == uuid.UUID(resposta.json()["id"]))) == nome
    assert "users" in inspect(get_engine()).get_table_names()  # a tabela continua lá


@pytest.mark.parametrize(
    "email", ["' OR '1'='1", "admin'--@x.com", "a@b.com' UNION SELECT password_hash FROM users--"]
)
def test_sql_injection_no_login_da_a_mesma_resposta_de_credencial_invalida(client, email):
    resposta = client.post("/api/v1/auth/login", json={"email": email, "password": "qualquer"})
    assert resposta.status_code == 401
    assert resposta.json()["code"] == "AUTH_001"


def test_nomes_reais_com_acento_e_apostrofo_passam(client):
    for nome in ("João D'Ávila", "María-José Ñúñez", "Zoë O'Brien"):
        assert _cadastrar(client, nome).status_code == 201, nome


def test_limites_de_tamanho_depois_de_normalizar():
    assert clean_text("a" * 120, min_length=2, max_length=120) == "a" * 120
    with pytest.raises(ValueError, match="máximo de 120"):
        clean_text("a" * 121, min_length=2, max_length=120)
    with pytest.raises(ValueError, match="mínimo de 2"):
        clean_text("   a   ", min_length=2, max_length=120)


# --------------------------------------------------------------- SQL: só consultas parametrizadas


def _consultas_montadas_com_texto() -> list[str]:
    """Chamadas a text()/execute()/exec_driver_sql() cujo SQL é f-string, concatenação, % ou .format()."""
    achados = []
    for arquivo in APP_DIR.rglob("*.py"):
        arvore = ast.parse(arquivo.read_text(encoding="utf-8"))
        for no in ast.walk(arvore):
            if not isinstance(no, ast.Call) or not no.args:
                continue
            nome = no.func.attr if isinstance(no.func, ast.Attribute) else getattr(no.func, "id", "")
            if nome not in {"text", "execute", "exec_driver_sql"}:
                continue
            sql = no.args[0]
            montado = isinstance(sql, ast.JoinedStr | ast.BinOp) or (
                isinstance(sql, ast.Call)
                and isinstance(sql.func, ast.Attribute)
                and sql.func.attr == "format"
            )
            if montado:
                achados.append(f"{arquivo.relative_to(APP_DIR)}:{no.lineno}")
    return achados


def test_nenhuma_consulta_sql_e_montada_concatenando_texto():
    assert _consultas_montadas_com_texto() == []


def test_a_varredura_pega_sql_montado(tmp_path, monkeypatch):
    # Prova de que o teste acima funciona: um arquivo com SQL concatenado é encontrado.
    pasta = tmp_path / "app"
    pasta.mkdir()
    (pasta / "ruim.py").write_text("db.execute(text(f\"SELECT * FROM users WHERE email = '{email}'\"))\n")
    monkeypatch.setattr("tests.test_text_input.APP_DIR", pasta)
    assert _consultas_montadas_com_texto() == ["ruim.py:1"]


# --------------------------------------------------------------- QA: invisíveis, vazios e emoji


@pytest.mark.parametrize(
    "texto",
    [
        ">",  # só o sinal
        "a>b",
        "＞",  # ＞ de largura cheia: o NFKC vira >
        "AnaSouza",  # uso privado (Co)
        "Ana͸Souza",  # não atribuído (Cn)
        "Ana\ud800Souza",  # surrogate solto (Cs)
        "Ana Souza",  # separador de linha (Zl)
        "Ana Souza",  # separador de parágrafo (Zp)
        "AnaㅤSouza",  # filler hangul
        "AnaᅟSouza",
        "AnaᅠSouza",
        "AnaﾠSouza",
        "Ana⠀Souza",  # braille vazio
        "a‍b",  # ZWJ entre letras
        "\U0001f468‍",  # ZWJ sem emoji depois
        "‍\U0001f468",  # ZWJ sem emoji antes
        "\U0001f468‍x",  # ZWJ antes de letra
        "\U0001f468​\U0001f469",  # espaço de largura zero entre emoji (outro Cf)
    ],
    ids=lambda t: "-".join(f"{ord(c):x}" for c in t),
)
def test_clean_text_recusa_invisiveis_e_caracteres_proibidos(texto):
    with pytest.raises(ValueError):
        clean_text(texto, min_length=1, max_length=60)


@pytest.mark.parametrize(
    "texto",
    ["ㅤ", "ㅤᅟᅠﾠ⠀", "⠀⠀⠀", " ", "     ", "́"],
    ids=["filler", "so-fillers", "braille", "zl", "so-espacos", "so-acento-solto"],
)
def test_clean_text_recusa_nome_sem_caractere_visivel(texto):
    with pytest.raises(ValueError):
        clean_text(texto, min_length=1, max_length=60)


def test_clean_text_aceita_emoji_com_zwj_e_variacoes():
    familia = "\U0001f468‍\U0001f469‍\U0001f467"  # 👨‍👩‍👧
    assert clean_text(familia, min_length=1, max_length=60) == familia
    coracao = "❤️‍\U0001f525"  # ❤️‍🔥: VS16 antes do ZWJ
    assert clean_text(coracao, min_length=1, max_length=60) == coracao
    tom = "\U0001f468\U0001f3fd‍\U0001f4bb"  # 👨🏽‍💻
    assert clean_text(tom, min_length=1, max_length=60) == tom
    assert clean_text(f"Ana {familia}", min_length=1, max_length=60) == f"Ana {familia}"


def test_clean_text_aceita_so_simbolo_ou_so_numero():
    assert clean_text("\U0001f600", min_length=1, max_length=60) == "\U0001f600"
    assert clean_text("123", min_length=1, max_length=60) == "123"


@pytest.mark.parametrize("nome", [">", "a>b", "＞", "Ana", "Ana͸", "Ana ", "ㅤㅤ"])
def test_cadastro_recusa_os_casos_da_qa(client, nome):
    resposta = _cadastrar(client, nome)
    assert resposta.status_code == 400
    assert resposta.json()["fields"][0]["field"] == "name"


def test_cadastro_aceita_emoji_de_familia_no_nome(client):
    familia = "\U0001f468‍\U0001f469‍\U0001f467"
    resposta = _cadastrar(client, f"Ana {familia}")
    assert resposta.status_code == 201
    assert resposta.json()["name"] == f"Ana {familia}"


def test_surrogate_solto_no_json_e_recusado_sem_erro_500(client):
    # "\ud800" escapado no JSON: se o parser deixar passar, o clean_text recusa; senão, é erro de corpo.
    corpo = (r'{"name": "Ana\ud800", "email": "surr@teste.dev", "password": "' + SENHA + '"}').encode()
    resposta = client.post(
        "/api/v1/auth/register", content=corpo, headers={"content-type": "application/json"}
    )
    assert resposta.status_code == 400
