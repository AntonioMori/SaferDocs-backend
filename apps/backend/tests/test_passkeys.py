"""Passkeys (REQ-06 a 10), com um autenticador WebAuthn de software."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app.crypto.jwt import decode_access_token
from app.db.models import AuditLog, SecurityEvent, WebauthnChallenge, WebauthnCredential
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


# --------------------------------------------------------------- contador de uso (REQ-08)


def _registrar_com_contador(client, conta, guardado):
    """Registra um autenticador e deixa o contador guardado no valor pedido."""
    autenticador = SoftAuthenticator()
    registrar(client, conta, autenticador)
    if guardado:
        assert entrar(client, autenticador, sign_count=guardado).status_code == 200
    assert _credencial_no_banco(conta["id"]).counter == guardado
    return autenticador


def _eventos(user_id):
    with get_sessionmaker()() as db:
        audit_rows = db.scalars(
            select(AuditLog.action).where(
                AuditLog.user_id == user_id, AuditLog.action == "PASSKEY_COUNTER_MISMATCH"
            )
        ).all()
        eventos = db.scalars(
            select(SecurityEvent.type).where(
                SecurityEvent.user_id == user_id, SecurityEvent.type == "PASSKEY_COUNTER_MISMATCH"
            )
        ).all()
    return len(audit_rows), len(eventos)


def test_contador_zero_e_zero_e_aceito(client, conta):
    # Passkey sincronizada manda sempre 0: não há o que comparar.
    autenticador = SoftAuthenticator(counts_up=False)
    registrar(client, conta, autenticador)
    assert entrar(client, autenticador).status_code == 200
    assert entrar(client, autenticador).status_code == 200
    assert _credencial_no_banco(conta["id"]).counter == 0


def test_contador_de_5_para_6_e_aceito_e_guardado(client, conta):
    autenticador = _registrar_com_contador(client, conta, 5)
    assert entrar(client, autenticador, sign_count=6).status_code == 200
    assert _credencial_no_banco(conta["id"]).counter == 6


def test_contador_igual_e_rejeitado(client, conta):
    autenticador = _registrar_com_contador(client, conta, 6)
    resposta = entrar(client, autenticador, sign_count=6)
    assert resposta.status_code == 400
    assert resposta.json()["code"] == "AUTH_006"
    assert _credencial_no_banco(conta["id"]).counter == 6


def test_contador_menor_e_rejeitado(client, conta):
    autenticador = _registrar_com_contador(client, conta, 6)
    assert entrar(client, autenticador, sign_count=3).status_code == 400
    assert _credencial_no_banco(conta["id"]).counter == 6


def test_contador_que_volta_para_zero_e_rejeitado(client, conta):
    autenticador = _registrar_com_contador(client, conta, 6)
    assert entrar(client, autenticador, sign_count=0).status_code == 400


def test_contador_que_sai_de_zero_e_aceito(client, conta):
    autenticador = _registrar_com_contador(client, conta, 0)
    assert entrar(client, autenticador, sign_count=1).status_code == 200


def test_rejeicao_por_contador_vai_para_auditoria_e_alerta_o_dono(client, conta):
    autenticador = _registrar_com_contador(client, conta, 6)
    assert _eventos(conta["id"]) == (0, 0)
    assert entrar(client, autenticador, sign_count=6).status_code == 400
    assert _eventos(conta["id"]) == (1, 1)


def test_rejeicao_por_contador_nao_cria_sessao(client, conta):
    autenticador = _registrar_com_contador(client, conta, 6)
    resposta = entrar(client, autenticador, sign_count=2)
    assert "access_token" not in resposta.json()
    assert not any(k == "set-cookie" and "refresh" in v for k, v in resposta.headers.multi_items())


# --------------------------------------------------------------- origin e rpId (REQ-09)

ORIGENS_ERRADAS = [
    "https://site-falso.example",  # outro domínio
    "http://localhost:9999",  # mesmo host, outra porta
    "https://localhost:3039",  # mesmo host, outro esquema
    "http://sub.localhost:3039",  # subdomínio
    "http://localhost.site-falso.example:3039",  # prefixo igual, domínio de outro
]


@pytest.mark.parametrize("origem", ORIGENS_ERRADAS)
def test_registro_de_outra_origem_e_rejeitado(client, conta, origem):
    resposta = registrar(client, conta, SoftAuthenticator(), origin=origem)
    assert resposta.status_code == 400
    assert resposta.json()["code"] == "AUTH_006"
    assert _credencial_no_banco(conta["id"]) is None


@pytest.mark.parametrize("origem", ORIGENS_ERRADAS)
def test_login_de_outra_origem_e_rejeitado(client, conta, origem):
    # Critério de aceite: asserção vinda de outra origem é rejeitada.
    autenticador = SoftAuthenticator()
    registrar(client, conta, autenticador)
    resposta = entrar(client, autenticador, origin=origem)
    assert resposta.status_code == 400
    assert resposta.json()["code"] == "AUTH_006"
    assert "access_token" not in resposta.json()


@pytest.mark.parametrize("rp_id", ["site-falso.example", "sub.localhost", "localhost.site-falso.example"])
def test_registro_com_rp_id_errado_e_rejeitado(client, conta, rp_id):
    resposta = registrar(client, conta, SoftAuthenticator(), rp_id=rp_id)
    assert resposta.status_code == 400
    assert _credencial_no_banco(conta["id"]) is None


@pytest.mark.parametrize("rp_id", ["site-falso.example", "sub.localhost", "localhost.site-falso.example"])
def test_login_com_rp_id_errado_e_rejeitado(client, conta, rp_id):
    autenticador = SoftAuthenticator()
    registrar(client, conta, autenticador)
    resposta = entrar(client, autenticador, rp_id=rp_id)
    assert resposta.status_code == 400
    assert resposta.json()["code"] == "AUTH_006"


def test_registro_com_cross_origin_e_rejeitado(client, conta):
    resposta = registrar(client, conta, SoftAuthenticator(), cross_origin=True)
    assert resposta.status_code == 400
    assert _credencial_no_banco(conta["id"]) is None


def test_login_com_cross_origin_e_rejeitado(client, conta):
    autenticador = SoftAuthenticator()
    registrar(client, conta, autenticador)
    resposta = entrar(client, autenticador, cross_origin=True)
    assert resposta.status_code == 400
    assert resposta.json()["code"] == "AUTH_006"


def test_falha_de_origem_nao_avanca_o_contador_nem_o_ultimo_uso(client, conta):
    autenticador = SoftAuthenticator()
    registrar(client, conta, autenticador)
    entrar(client, autenticador, origin="https://site-falso.example")
    guardada = _credencial_no_banco(conta["id"])
    assert guardada.counter == 0
    assert guardada.last_used_at is None


def test_origem_certa_continua_funcionando_depois_de_uma_recusa(client, conta):
    autenticador = SoftAuthenticator()
    registrar(client, conta, autenticador)
    assert entrar(client, autenticador, origin="https://site-falso.example").status_code == 400
    assert entrar(client, autenticador).status_code == 200


def test_opcoes_usam_o_rp_id_da_configuracao(client, conta):
    from app.core.config import get_settings

    settings = get_settings()
    registro = client.post("/api/v1/auth/passkeys/register/options", headers=conta["headers"]).json()
    login = client.post("/api/v1/auth/passkeys/login/options").json()
    assert registro["rp"]["id"] == login["rpId"] == settings.webauthn_rp_id


# --------------------------------------------------------------- gerenciamento (REQ-10)

URL = "/api/v1/auth/passkeys"


@pytest.fixture
def outra_conta(client):
    email = f"pk-{uuid.uuid4().hex[:10]}@teste.dev"
    user_id = uuid.UUID(
        client.post(
            "/api/v1/auth/register", json={"name": "Bia Souza", "email": email, "password": SENHA}
        ).json()["id"]
    )
    return {"id": user_id, "headers": {"Authorization": f"Bearer {session_token(user_id)}"}}


def _acoes_de_auditoria(user_id, acao):
    with get_sessionmaker()() as db:
        return len(
            db.scalars(select(AuditLog.id).where(AuditLog.user_id == user_id, AuditLog.action == acao)).all()
        )


def test_gerenciamento_exige_autenticacao(client, conta):
    registrado = registrar(client, conta, SoftAuthenticator()).json()["id"]
    assert client.get(URL).status_code == 401
    assert client.put(f"{URL}/{registrado}", json={"name": "x"}).status_code == 401
    assert client.delete(f"{URL}/{registrado}").status_code == 401


def test_lista_so_as_passkeys_do_proprio_usuario(client, conta, outra_conta):
    minha = registrar(client, conta, SoftAuthenticator(), nome="Notebook").json()["id"]
    registrar(client, outra_conta, SoftAuthenticator(), nome="Celular da Bia")
    resposta = client.get(URL, headers=conta["headers"])
    assert resposta.status_code == 200
    assert [p["id"] for p in resposta.json()] == [minha]


def test_lista_vazia_sem_passkeys(client, conta):
    assert client.get(URL, headers=conta["headers"]).json() == []


def test_lista_so_devolve_campos_publicos(client, conta):
    registrar(client, conta, SoftAuthenticator())
    item = client.get(URL, headers=conta["headers"]).json()[0]
    assert set(item) == {"id", "name", "aaguid", "transports", "created_at", "last_used_at"}


def test_lista_mostra_o_ultimo_uso_depois_do_login(client, conta):
    autenticador = SoftAuthenticator()
    registrar(client, conta, autenticador)
    assert client.get(URL, headers=conta["headers"]).json()[0]["last_used_at"] is None
    entrar(client, autenticador)
    assert client.get(URL, headers=conta["headers"]).json()[0]["last_used_at"] is not None


def test_renomeia_a_propria_passkey_e_audita(client, conta):
    passkey_id = registrar(client, conta, SoftAuthenticator()).json()["id"]
    resposta = client.put(
        f"{URL}/{passkey_id}", json={"name": "  Notebook   do trabalho "}, headers=conta["headers"]
    )
    assert resposta.status_code == 200
    assert resposta.json()["name"] == "Notebook do trabalho"
    assert client.get(URL, headers=conta["headers"]).json()[0]["name"] == "Notebook do trabalho"
    assert _acoes_de_auditoria(conta["id"], "PASSKEY_RENAMED") == 1


@pytest.mark.parametrize(
    "corpo", [{"name": ""}, {"name": "   "}, {"name": "<b>"}, {"name": "a" * 61}, {}, {"name": "ok", "x": 1}]
)
def test_renomear_com_nome_invalido_e_recusado(client, conta, corpo):
    passkey_id = registrar(client, conta, SoftAuthenticator(), nome="Original").json()["id"]
    assert client.put(f"{URL}/{passkey_id}", json=corpo, headers=conta["headers"]).status_code == 400
    assert client.get(URL, headers=conta["headers"]).json()[0]["name"] == "Original"


def test_renomear_passkey_de_outro_usuario_da_404_e_nao_altera(client, conta, outra_conta):
    alheia = registrar(client, outra_conta, SoftAuthenticator(), nome="Da Bia").json()["id"]
    resposta = client.put(f"{URL}/{alheia}", json={"name": "Invadida"}, headers=conta["headers"])
    assert resposta.status_code == 404
    assert client.get(URL, headers=outra_conta["headers"]).json()[0]["name"] == "Da Bia"
    assert _acoes_de_auditoria(conta["id"], "PASSKEY_RENAMED") == 0


def test_revogar_passkey_de_outro_usuario_da_404_e_nao_apaga(client, conta, outra_conta):
    alheia = registrar(client, outra_conta, SoftAuthenticator()).json()["id"]
    assert client.delete(f"{URL}/{alheia}", headers=conta["headers"]).status_code == 404
    assert len(client.get(URL, headers=outra_conta["headers"]).json()) == 1


def test_404_de_passkey_alheia_e_igual_ao_de_passkey_inexistente(client, conta, outra_conta):
    alheia = registrar(client, outra_conta, SoftAuthenticator()).json()["id"]
    inexistente = str(uuid.uuid4())
    for metodo, corpo in (("put", {"json": {"name": "x"}}), ("delete", {})):
        a = getattr(client, metodo)(f"{URL}/{alheia}", headers=conta["headers"], **corpo)
        b = getattr(client, metodo)(f"{URL}/{inexistente}", headers=conta["headers"], **corpo)
        assert a.status_code == b.status_code == 404
        assert {**a.json(), "request_id": ""} == {**b.json(), "request_id": ""}


def test_id_que_nao_e_uuid_e_erro_de_validacao(client, conta):
    assert client.delete(f"{URL}/nao-e-uuid", headers=conta["headers"]).status_code == 400


def test_passkey_revogada_nao_autentica_mais(client, conta):
    # Critério de aceite: passkey revogada não autentica mais.
    autenticador = SoftAuthenticator()
    passkey_id = registrar(client, conta, autenticador).json()["id"]
    assert entrar(client, autenticador).status_code == 200
    assert client.delete(f"{URL}/{passkey_id}", headers=conta["headers"]).status_code == 204
    resposta = entrar(client, autenticador)
    assert resposta.status_code == 400
    assert resposta.json()["code"] == "AUTH_006"
    assert client.get(URL, headers=conta["headers"]).json() == []


def test_revogar_audita_e_nao_apaga_as_outras(client, conta):
    primeira, segunda = SoftAuthenticator(), SoftAuthenticator()
    id_primeira = registrar(client, conta, primeira).json()["id"]
    id_segunda = registrar(client, conta, segunda).json()["id"]
    assert client.delete(f"{URL}/{id_primeira}", headers=conta["headers"]).status_code == 204
    assert _acoes_de_auditoria(conta["id"], "PASSKEY_REVOKED") == 1
    assert [p["id"] for p in client.get(URL, headers=conta["headers"]).json()] == [id_segunda]
    assert entrar(client, segunda).status_code == 200


def test_revogar_duas_vezes_da_404_na_segunda(client, conta):
    passkey_id = registrar(client, conta, SoftAuthenticator()).json()["id"]
    assert client.delete(f"{URL}/{passkey_id}", headers=conta["headers"]).status_code == 204
    assert client.delete(f"{URL}/{passkey_id}", headers=conta["headers"]).status_code == 404


def test_registro_audita_a_passkey_registrada(client, conta):
    registrar(client, conta, SoftAuthenticator())
    assert _acoes_de_auditoria(conta["id"], "PASSKEY_REGISTERED") == 1


def test_mesmo_dispositivo_pode_ser_registrado_de_novo_depois_de_revogado(client, conta):
    autenticador = SoftAuthenticator()
    passkey_id = registrar(client, conta, autenticador).json()["id"]
    client.delete(f"{URL}/{passkey_id}", headers=conta["headers"])
    assert registrar(client, conta, autenticador).status_code == 201
