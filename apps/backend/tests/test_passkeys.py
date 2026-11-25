"""Passkeys (REQ-06 a 10), com um autenticador WebAuthn de software."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app.crypto.jwt import decode_access_token
from app.db.models import WebauthnChallenge, WebauthnCredential
from app.db.session import get_sessionmaker
from app.main import app
from tests.conftest import session_token
from tests.webauthn_soft import SoftAuthenticator

SENHA = "Senha-Forte#2026"
FRONT = "http://localhost:3039"


@pytest.fixture
def client(migrated_db):
    return TestClient(app, headers={"Origin": FRONT})


@pytest.fixture
def conta(client):
    email = f"pk-{uuid.uuid4().hex[:10]}@teste.dev"
    user_id = client.post(
        "/api/v1/auth/register", json={"name": "Ana Lima", "email": email, "password": SENHA}
    ).json()["id"]
    return {
        "id": uuid.UUID(user_id),
        "email": email,
        "headers": {"Authorization": f"Bearer {session_token(uuid.UUID(user_id))}"},
    }


def registrar(client, conta, autenticador, nome=None, **kwargs):
    opcoes = client.post("/api/v1/auth/passkeys/register/options", headers=conta["headers"]).json()
    corpo = {"credential": autenticador.create(opcoes, **kwargs)}
    if nome is not None:
        corpo["name"] = nome
    return client.post("/api/v1/auth/passkeys/register/verify", json=corpo, headers=conta["headers"])


def entrar(client, autenticador, **kwargs):
    opcoes = client.post("/api/v1/auth/passkeys/login/options").json()
    return client.post(
        "/api/v1/auth/passkeys/login/verify", json={"credential": autenticador.get(opcoes, **kwargs)}
    )


# --------------------------------------------------------------- cerimônias (REQ-06)


def test_registro_e_login_com_passkey(client, conta):
    # Critério de aceite: registro e login com passkey funcionam.
    autenticador = SoftAuthenticator()
    registro = registrar(client, conta, autenticador)
    assert registro.status_code == 201, registro.text
    login = entrar(client, autenticador)
    assert login.status_code == 200, login.text
    corpo = login.json()
    assert decode_access_token(corpo["access_token"])["sub"] == str(conta["id"])
    assert corpo["user"]["email"] == conta["email"]
    assert any(k == "set-cookie" and "refresh" in v for k, v in login.headers.multi_items())


def test_opcoes_de_registro_pedem_passkey_descobrivel_e_verificacao(client, conta):
    opcoes = client.post("/api/v1/auth/passkeys/register/options", headers=conta["headers"]).json()
    assert opcoes["rp"]["id"] == "localhost"
    assert opcoes["authenticatorSelection"]["residentKey"] == "required"
    assert opcoes["authenticatorSelection"]["userVerification"] == "required"
    assert len(opcoes["challenge"]) >= 43  # 32 bytes aleatórios em base64url


def test_opcoes_de_login_nao_pedem_email(client):
    opcoes = client.post("/api/v1/auth/passkeys/login/options").json()
    assert opcoes.get("allowCredentials", []) == []
    assert opcoes["userVerification"] == "required"


def test_registro_exige_autenticacao(client):
    assert client.post("/api/v1/auth/passkeys/register/options").status_code == 401


def test_desafio_e_de_uso_unico(client, conta):
    autenticador = SoftAuthenticator()
    registrar(client, conta, autenticador)
    opcoes = client.post("/api/v1/auth/passkeys/login/options").json()
    assercao = autenticador.get(opcoes)
    assert client.post("/api/v1/auth/passkeys/login/verify", json={"credential": assercao}).status_code == 200
    replay = client.post("/api/v1/auth/passkeys/login/verify", json={"credential": assercao})
    assert replay.status_code == 400
    assert replay.json()["code"] == "AUTH_006"


def test_desafio_expirado_e_recusado(client, conta):
    autenticador = SoftAuthenticator()
    registrar(client, conta, autenticador)
    opcoes = client.post("/api/v1/auth/passkeys/login/options").json()
    with get_sessionmaker()() as db:
        db.execute(update(WebauthnChallenge).values(expires_at=datetime.now(UTC) - timedelta(seconds=1)))
        db.commit()
    resposta = client.post(
        "/api/v1/auth/passkeys/login/verify", json={"credential": autenticador.get(opcoes)}
    )
    assert resposta.status_code == 400


def test_desafio_inventado_e_recusado(client, conta):
    autenticador = SoftAuthenticator()
    registrar(client, conta, autenticador)
    falso = {"challenge": "A" * 43}
    resposta = client.post("/api/v1/auth/passkeys/login/verify", json={"credential": autenticador.get(falso)})
    assert resposta.status_code == 400


def test_desafio_de_registro_nao_serve_para_login(client, conta):
    autenticador = SoftAuthenticator()
    registrar(client, conta, autenticador)
    opcoes_registro = client.post("/api/v1/auth/passkeys/register/options", headers=conta["headers"]).json()
    resposta = client.post(
        "/api/v1/auth/passkeys/login/verify", json={"credential": autenticador.get(opcoes_registro)}
    )
    assert resposta.status_code == 400


def test_assinatura_de_outra_chave_e_recusada(client, conta):
    autenticador = SoftAuthenticator()
    registrar(client, conta, autenticador)
    impostor = SoftAuthenticator(
        credential_id=autenticador.credential_id, user_handle=autenticador.user_handle
    )
    resposta = entrar(client, impostor)
    assert resposta.status_code == 400
    assert resposta.json()["code"] == "AUTH_006"


def test_credencial_desconhecida_e_recusada(client):
    resposta = entrar(client, SoftAuthenticator(user_handle=b"x"))
    assert resposta.status_code == 400


def test_sem_verificacao_do_usuario_e_recusado(client, conta):
    autenticador = SoftAuthenticator()
    registrar(client, conta, autenticador)
    autenticador.user_verified = False
    assert entrar(client, autenticador).status_code == 400


def test_mesmo_autenticador_nao_e_registrado_duas_vezes(client, conta):
    autenticador = SoftAuthenticator()
    assert registrar(client, conta, autenticador).status_code == 201
    assert registrar(client, conta, autenticador).status_code == 400


def test_login_com_passkey_tem_rate_limit_por_ip(client, monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "rate_limit_login_per_ip", "2/minute")
    respostas = [client.post("/api/v1/auth/passkeys/login/options") for _ in range(3)]
    assert [r.status_code for r in respostas] == [200, 200, 429]


def test_corpo_fora_do_formato_e_erro_de_validacao(client):
    for corpo in ({"credential": {"id": "x"}}, {"credential": "texto"}, {}):
        assert client.post("/api/v1/auth/passkeys/login/verify", json=corpo).status_code == 400


# --------------------------------------------------------------- dados do dispositivo (REQ-07)


def _credencial_no_banco(user_id):
    with get_sessionmaker()() as db:
        return db.scalar(select(WebauthnCredential).where(WebauthnCredential.user_id == user_id))


def test_registro_persiste_os_quatro_campos_do_dispositivo(client, conta):
    # Critério de aceite: credentialId, publicKey, counter e aaguid são persistidos no registro.
    autenticador = SoftAuthenticator(sign_count=0)
    assert registrar(client, conta, autenticador).status_code == 201
    guardada = _credencial_no_banco(conta["id"])
    assert guardada.credential_id == autenticador.credential_id
    assert guardada.public_key
    assert guardada.counter == 0
    assert guardada.aaguid == autenticador.aaguid


def test_registro_guarda_nome_transportes_e_datas(client, conta):
    resposta = registrar(client, conta, SoftAuthenticator(), nome="  Meu   notebook ")
    assert resposta.status_code == 201
    corpo = resposta.json()
    assert corpo["name"] == "Meu notebook"
    assert corpo["transports"] == ["internal", "hybrid"]
    assert corpo["created_at"]
    assert corpo["last_used_at"] is None


def test_nome_padrao_quando_nao_informado(client, conta):
    assert registrar(client, conta, SoftAuthenticator()).json()["name"] == "Passkey"


@pytest.mark.parametrize("nome", ["<script>", "", "   ", "a" * 61, "nome‮oculto"])
def test_nome_invalido_e_recusado(client, conta, nome):
    assert registrar(client, conta, SoftAuthenticator(), nome=nome).status_code == 400


def test_resposta_do_registro_nao_expoe_chave_publica_nem_contador(client, conta):
    corpo = registrar(client, conta, SoftAuthenticator()).json()
    assert "public_key" not in corpo
    assert "counter" not in corpo
    assert "credential_id" not in corpo


def test_ultimo_uso_e_atualizado_no_login(client, conta):
    autenticador = SoftAuthenticator()
    registrar(client, conta, autenticador)
    assert _credencial_no_banco(conta["id"]).last_used_at is None
    assert entrar(client, autenticador).status_code == 200
    assert _credencial_no_banco(conta["id"]).last_used_at is not None
