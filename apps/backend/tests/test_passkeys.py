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


# --------------------------------------------------------------- QA: limpeza, limites, corrida, bloqueio


def _desafios(**filtros):
    with get_sessionmaker()() as db:
        consulta = select(WebauthnChallenge)
        for coluna, valor in filtros.items():
            consulta = consulta.where(getattr(WebauthnChallenge, coluna) == valor)
        return list(db.scalars(consulta.order_by(WebauthnChallenge.created_at)))


def _desafio_vencido(ha):
    with get_sessionmaker()() as db:
        desafio = WebauthnChallenge(
            user_id=None,
            challenge=uuid.uuid4().bytes * 2,
            kind="login",
            expires_at=datetime.now(UTC) - ha,
        )
        db.add(desafio)
        db.commit()
        return desafio.challenge


def test_desafio_vencido_ha_mais_de_um_dia_e_apagado_ao_criar_outro(client):
    velho = _desafio_vencido(timedelta(days=2))
    recente = _desafio_vencido(timedelta(hours=1))
    assert client.post("/api/v1/auth/passkeys/login/options").status_code == 200
    restantes = {d.challenge for d in _desafios()}
    assert velho not in restantes
    assert recente in restantes  # ainda dentro da retenção


def test_ttl_do_desafio_e_de_cinco_minutos(client, conta):
    client.post("/api/v1/auth/passkeys/register/options", headers=conta["headers"])
    desafio = _desafios(user_id=conta["id"])[0]
    restante = (desafio.expires_at - datetime.now(UTC)).total_seconds()
    assert abs(restante - 300) <= 2


def test_rate_limit_do_login_tem_escopo_proprio_para_options_e_verify(client, monkeypatch):
    from app.core.config import get_settings
    from app.middlewares.rate_limit import reset_rate_limits

    autenticador = SoftAuthenticator(user_handle=b"x")
    opcoes = client.post("/api/v1/auth/passkeys/login/options").json()
    corpo = {"credential": autenticador.get(opcoes)}
    monkeypatch.setattr(get_settings(), "rate_limit_login_per_ip", "2/minute")
    reset_rate_limits()
    # Encher o options não gasta vaga do verify.
    assert [client.post("/api/v1/auth/passkeys/login/options").status_code for _ in range(3)] == [
        200,
        200,
        429,
    ]
    verify = [client.post("/api/v1/auth/passkeys/login/verify", json=corpo).status_code for _ in range(3)]
    assert verify == [400, 400, 429]  # o verify tem o limite dele, e chega ao 429


def test_rate_limit_do_registro_por_usuario_com_escopo_para_cada_rota(
    client, conta, outra_conta, monkeypatch
):
    from app.core.config import get_settings
    from app.middlewares.rate_limit import reset_rate_limits

    url = "/api/v1/auth/passkeys/register"
    opcoes = client.post(f"{url}/options", headers=conta["headers"]).json()
    corpo = {"credential": SoftAuthenticator().create(opcoes)}
    monkeypatch.setattr(get_settings(), "rate_limit_passkey_register_per_user", "2/minute")
    reset_rate_limits()
    por_opcoes = [client.post(f"{url}/options", headers=conta["headers"]).status_code for _ in range(3)]
    assert por_opcoes == [200, 200, 429]
    verify = [
        client.post(f"{url}/verify", json=corpo, headers=conta["headers"]).status_code for _ in range(3)
    ]
    assert verify[2] == 429  # o verify tem o limite dele
    # Outro usuário, mesmo IP: não é afetado.
    assert client.post(f"{url}/options", headers=outra_conta["headers"]).status_code == 200


def test_transportes_desconhecidos_sao_descartados(client, conta):
    autenticador = SoftAuthenticator(transports=["internal", "<img>", "usb", "usb", "x" * 20, "hybrid"])
    resposta = registrar(client, conta, autenticador)
    assert resposta.status_code == 201
    assert resposta.json()["transports"] == ["internal", "usb", "hybrid"]
    assert _credencial_no_banco(conta["id"]).transports == ["internal", "usb", "hybrid"]


def _inserir_credenciais(user_id, quantidade):
    with get_sessionmaker()() as db:
        for _ in range(quantidade):
            db.add(
                WebauthnCredential(
                    user_id=user_id,
                    credential_id=uuid.uuid4().bytes * 2,
                    public_key=b"x",
                    counter=0,
                    aaguid=uuid.uuid4(),
                    name="Antiga",
                )
            )
        db.commit()


def test_limite_de_20_passkeys_a_vigesima_passa_e_a_vigesima_primeira_nao(client, conta):
    _inserir_credenciais(conta["id"], 19)
    assert registrar(client, conta, SoftAuthenticator()).status_code == 201  # a 20a
    recusada = registrar(client, conta, SoftAuthenticator())
    assert recusada.status_code == 400
    assert recusada.json()["code"] == "AUTH_006"
    assert len(client.get(URL, headers=conta["headers"]).json()) == 20


def test_registro_simultaneo_da_mesma_credencial_vira_falha_da_cerimonia_e_nao_500(
    client, conta, outra_conta, monkeypatch
):
    from app.services import passkey_service

    autenticador = SoftAuthenticator()
    original = passkey_service.audit.record

    def gravar_concorrente(db, **kwargs):
        # Outra requisição grava a mesma credencial depois da conferência e antes do commit
        # (de outro usuário: a linha do usuário em registro está travada).
        if kwargs["action"] == passkey_service.audit.AuditAction.PASSKEY_REGISTERED:
            with get_sessionmaker()() as outra:
                outra.add(
                    WebauthnCredential(
                        user_id=outra_conta["id"],
                        credential_id=autenticador.credential_id,
                        public_key=b"x",
                        counter=0,
                        aaguid=uuid.uuid4(),
                        name="Concorrente",
                    )
                )
                outra.commit()
        return original(db, **kwargs)

    monkeypatch.setattr(passkey_service.audit, "record", gravar_concorrente)
    resposta = registrar(client, conta, autenticador)
    assert resposta.status_code == 400
    assert resposta.json()["code"] == "AUTH_006"
    assert client.get(URL, headers=conta["headers"]).json() == []


def test_desafio_de_registro_de_outro_usuario_e_recusado(client, conta, outra_conta):
    # O desafio de A não vale para B: cada desafio é amarrado a quem o pediu.
    opcoes_de_a = client.post("/api/v1/auth/passkeys/register/options", headers=conta["headers"]).json()
    credencial = SoftAuthenticator().create(opcoes_de_a)
    resposta = client.post(
        "/api/v1/auth/passkeys/register/verify",
        json={"credential": credencial},
        headers=outra_conta["headers"],
    )
    assert resposta.status_code == 400
    assert _credencial_no_banco(outra_conta["id"]) is None
    assert _credencial_no_banco(conta["id"]) is None


def test_registro_sem_verificacao_do_usuario_e_recusado(client, conta):
    resposta = registrar(client, conta, SoftAuthenticator(user_verified=False))
    assert resposta.status_code == 400
    assert _credencial_no_banco(conta["id"]) is None


def test_replay_com_contador_zero_so_e_barrado_pelo_desafio_de_uso_unico(client, conta):
    autenticador = SoftAuthenticator(counts_up=False, sign_count=0)
    registrar(client, conta, autenticador)
    opcoes = client.post("/api/v1/auth/passkeys/login/options").json()
    assercao = autenticador.get(opcoes)
    assert client.post("/api/v1/auth/passkeys/login/verify", json={"credential": assercao}).status_code == 200
    replay = client.post("/api/v1/auth/passkeys/login/verify", json={"credential": assercao})
    assert replay.status_code == 400
    assert replay.json()["code"] == "AUTH_006"
    assert _credencial_no_banco(conta["id"]).counter == 0
    assert _desafios(kind="login")[-1].used_at is not None


def test_assercao_recusada_queima_o_desafio(client, conta):
    autenticador = SoftAuthenticator()
    registrar(client, conta, autenticador)
    impostor = SoftAuthenticator(
        credential_id=autenticador.credential_id, user_handle=autenticador.user_handle
    )
    assert entrar(client, impostor).status_code == 400
    assert _desafios(kind="login")[-1].used_at is not None


def test_contador_que_nao_subiu_audita_com_o_dono_e_nao_mexe_na_credencial(client, conta):
    autenticador = _registrar_com_contador(client, conta, 6)
    antes = _credencial_no_banco(conta["id"])
    assert entrar(client, autenticador, sign_count=6).status_code == 400
    depois = _credencial_no_banco(conta["id"])
    assert (depois.counter, depois.last_used_at) == (antes.counter, antes.last_used_at)
    with get_sessionmaker()() as db:
        auditoria = db.scalars(select(AuditLog).where(AuditLog.action == "PASSKEY_COUNTER_MISMATCH")).all()
        eventos = db.scalars(
            select(SecurityEvent).where(SecurityEvent.type == "PASSKEY_COUNTER_MISMATCH")
        ).all()
    assert [a.user_id for a in auditoria if a.details["credential"] == str(antes.id)] == [conta["id"]]
    assert [e.user_id for e in eventos if e.details["credential"] == str(antes.id)] == [conta["id"]]


@pytest.mark.parametrize(
    "marcas",
    [{"cross_origin": True}, {"top_origin": True}, {"cross_origin": True, "top_origin": True}],
    ids=["so-crossOrigin", "so-topOrigin", "os-dois"],
)
def test_registro_e_login_recusam_crossorigin_e_toporigin_cada_um_sozinho(client, conta, marcas):
    assert registrar(client, conta, SoftAuthenticator(), **marcas).status_code == 400
    assert _credencial_no_banco(conta["id"]) is None
    autenticador = SoftAuthenticator()
    assert registrar(client, conta, autenticador).status_code == 201
    resposta = entrar(client, autenticador, **marcas)
    assert resposta.status_code == 400
    assert resposta.json()["code"] == "AUTH_006"


def test_login_com_passkey_ignora_o_bloqueio_da_senha_e_zera_o_bloqueio(client, conta):
    # Decisão (README): a passkey é um fator forte e resistente a phishing; o bloqueio existe
    # para barrar quem adivinha senha. Por isso o login com passkey passa e limpa o bloqueio.
    from app.db.models import User

    autenticador = SoftAuthenticator()
    registrar(client, conta, autenticador)
    with get_sessionmaker()() as db:
        usuario = db.get(User, conta["id"])
        usuario.locked_until = datetime.now(UTC) + timedelta(minutes=15)
        usuario.failed_login_count = 5
        db.commit()
    senha = client.post("/api/v1/auth/login", json={"email": conta["email"], "password": SENHA})
    assert senha.status_code != 200  # o bloqueio vale para a senha
    assert entrar(client, autenticador).status_code == 200
    with get_sessionmaker()() as db:
        usuario = db.get(User, conta["id"])
        assert usuario.locked_until is None
        assert usuario.failed_login_count == 0
