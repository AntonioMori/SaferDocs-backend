"""REQ-01: política de senhas no cadastro."""

import uuid

import pytest
from fastapi.testclient import TestClient

from app.core.password_policy import password_policy_violations
from app.db.session import get_sessionmaker
from app.main import app
from app.services.auth_service import find_user_by_email

FORTE = "Senha-Forte#2026"


@pytest.mark.parametrize(
    ("senha", "falta"),
    [
        ("Ab1!", "mínimo de 12 caracteres"),
        ("senha-forte#2026", "ao menos uma letra maiúscula"),
        ("SENHA-FORTE#2026", "ao menos uma letra minúscula"),
        ("Senha-Forte#Doze", "ao menos um número"),
        ("SenhaForte2026Ab", "ao menos um símbolo"),
        ("Aa1!" + "x" * 130, "máximo de 128 caracteres"),
    ],
)
def test_cada_regra_da_politica(senha, falta):
    assert falta in password_policy_violations(senha)


def test_senha_forte_passa():
    assert password_policy_violations(FORTE) == []
    assert password_policy_violations("Çãéü Ñ 1234 ☂x") == []  # Unicode e espaço contam


def _email() -> str:
    return f"user-{uuid.uuid4().hex[:10]}@teste.dev"


@pytest.fixture
def client(migrated_db):
    return TestClient(app)


def test_cadastro_com_senha_forte(client):
    email = _email()
    resposta = client.post(
        "/api/v1/auth/register", json={"name": "  Ana   Souza ", "email": email.upper(), "password": FORTE}
    )
    assert resposta.status_code == 201
    corpo = resposta.json()
    assert corpo["name"] == "Ana Souza"
    assert corpo["email"] == email
    assert set(corpo) == {"id", "name", "email"}  # nada de hash na resposta

    with get_sessionmaker()() as db:
        user = find_user_by_email(db, email)
        assert user.password_hash.startswith("$argon2id$")


def test_cadastro_com_senha_fraca_lista_as_regras(client):
    resposta = client.post(
        "/api/v1/auth/register", json={"name": "Ana", "email": _email(), "password": "fraca"}
    )
    assert resposta.status_code == 400
    campo = resposta.json()["fields"][0]
    assert campo["field"] == "password"
    for regra in ("mínimo de 12 caracteres", "maiúscula", "número", "símbolo"):
        assert regra in campo["reason"]
    assert "fraca" not in resposta.text


def test_email_duplicado_sem_diferenciar_maiusculas(client):
    email = _email()
    assert (
        client.post(
            "/api/v1/auth/register", json={"name": "A1", "email": email, "password": FORTE}
        ).status_code
        == 201
    )
    resposta = client.post(
        "/api/v1/auth/register", json={"name": "A2", "email": email.upper(), "password": FORTE}
    )
    assert resposta.status_code == 400
    assert resposta.json()["fields"] == [{"field": "email", "reason": "e-mail já cadastrado"}]


def test_email_invalido(client):
    resposta = client.post(
        "/api/v1/auth/register", json={"name": "Ana", "email": "nao-e-email", "password": FORTE}
    )
    assert resposta.status_code == 400
    assert resposta.json()["fields"][0]["field"] == "email"
