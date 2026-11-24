"""INFRA-02: interfaces compartilhadas entre os dois lados do projeto.

Estes testes fixam as assinaturas combinadas. A implementação real de cada
interface pode mudar por dentro, mas estes chamadores precisam continuar
funcionando.
"""

import inspect
import uuid

import pytest
from fastapi import APIRouter, Request, Response
from fastapi.testclient import TestClient
from sqlalchemy import inspect as sa_inspect

from app.api.deps import CurrentUser
from app.crypto import aead
from app.crypto.jwt import encode_access_token
from app.db.models import User
from app.db.session import get_engine, get_sessionmaker
from app.main import create_app
from app.middlewares import rate_limit
from app.pdf import client as pdf_client
from app.services import audit_service, security_events, token_service, user_keys
from tests.conftest import make_pdf, session_token

TABELAS = {
    "users",
    "recovery_codes",
    "mfa_challenges",
    "sessions",
    "refresh_tokens",
    "jwt_denylist",
    "webauthn_credentials",
    "webauthn_challenges",
    "signatures",
    "audit_log",
    "security_events",
    "known_ips",
}


# ------------------------------------------------------------------ schema


def test_migracao_cria_todas_as_tabelas_do_projeto(migrated_db):
    assert TABELAS <= set(sa_inspect(get_engine()).get_table_names())


# ------------------------------------------------------------------ AES-GCM


def test_aead_ida_e_volta():
    cifrado = aead.encrypt(aead.AeadContext.TOTP_SECRET, b"segredo", b"user-1")
    assert b"segredo" not in cifrado
    assert aead.decrypt(aead.AeadContext.TOTP_SECRET, cifrado, b"user-1") == b"segredo"


def test_aead_nonce_aleatorio():
    a = aead.encrypt(aead.AeadContext.TOTP_SECRET, b"x")
    b = aead.encrypt(aead.AeadContext.TOTP_SECRET, b"x")
    assert a != b


def test_aead_detecta_adulteracao():
    cifrado = bytearray(aead.encrypt(aead.AeadContext.SIGNING_KEY, b"chave privada"))
    cifrado[-1] ^= 1
    with pytest.raises(aead.DecryptionError):
        aead.decrypt(aead.AeadContext.SIGNING_KEY, bytes(cifrado))


def test_aead_contextos_e_dono_nao_se_misturam():
    cifrado = aead.encrypt(aead.AeadContext.TOTP_SECRET, b"x", b"user-1")
    with pytest.raises(aead.DecryptionError):
        aead.decrypt(aead.AeadContext.SIGNING_KEY, cifrado, b"user-1")
    with pytest.raises(aead.DecryptionError):
        aead.decrypt(aead.AeadContext.TOTP_SECRET, cifrado, b"user-2")


# ------------------------------------------------------------------ get_current_user

router = APIRouter(prefix="/api/v1/_teste")


@router.get("/eu")
def _eu(user: CurrentUser):
    return {"email": user.email}


@pytest.fixture(scope="module")
def client():
    app = create_app()
    app.include_router(router)
    return TestClient(app)


@pytest.fixture
def usuario(migrated_db):
    with get_sessionmaker()() as db:
        user = User(name="Ana", email=f"ana-{uuid.uuid4().hex[:8]}@teste.dev", password_hash="!")
        db.add(user)
        db.commit()
        yield user
        db.delete(user)
        db.commit()


def test_rota_protegida_aceita_token_valido(client, usuario):
    token = session_token(usuario.id)
    resposta = client.get("/api/v1/_teste/eu", headers={"Authorization": f"Bearer {token}"})
    assert resposta.status_code == 200
    assert resposta.json() == {"email": usuario.email}


@pytest.mark.parametrize("cabecalho", [None, "Bearer invalido", "Basic abc"])
def test_rota_protegida_recusa_sem_token_valido(client, migrated_db, cabecalho):
    headers = {"Authorization": cabecalho} if cabecalho else {}
    resposta = client.get("/api/v1/_teste/eu", headers=headers)
    assert resposta.status_code == 401
    assert resposta.json()["code"] == "AUTH_003"


def test_token_de_usuario_inexistente_e_recusado(client, migrated_db):
    token, _ = encode_access_token(uuid.uuid4())
    resposta = client.get("/api/v1/_teste/eu", headers={"Authorization": f"Bearer {token}"})
    assert resposta.status_code == 401


# ------------------------------------------------------------------ assinaturas dos stubs


def _parametros(funcao) -> list[str]:
    return list(inspect.signature(funcao).parameters)


def test_assinaturas_combinadas():
    assert _parametros(token_service.issue_tokens) == ["db", "user", "request", "response"]
    assert _parametros(audit_service.record) == ["db", "action", "result", "request", "user_id", "details"]
    assert _parametros(security_events.emit) == ["db", "user_id", "type", "request", "details"]
    assert _parametros(rate_limit.check_rate_limit) == ["scope", "key", "limit"]
    assert _parametros(rate_limit.limit_by_ip) == ["scope", "limit"]
    assert _parametros(user_keys.generate_user_keys) == ["db", "user"]
    assert _parametros(pdf_client.prepare_sign) == ["pdf", "page", "x", "y", "seal_lines", "signer_cert_pem"]
    assert _parametros(pdf_client.finish_sign) == ["prepared_pdf", "cms"]
    assert _parametros(pdf_client.verify) == ["pdf"]


def test_stubs_podem_ser_chamados(usuario, fake_pdf_worker):
    request = Request({"type": "http", "headers": [], "client": ("127.0.0.1", 1)})
    with get_sessionmaker()() as db:
        emitidos = token_service.issue_tokens(db, usuario, request, Response())
        assert emitidos.access_token and emitidos.token_type == "Bearer"
        audit_service.record(
            db,
            action=audit_service.AuditAction.LOGIN,
            result=audit_service.AuditResult.SUCCESS,
            request=request,
            user_id=usuario.id,
        )
        security_events.emit(
            db, user_id=usuario.id, type=security_events.SecurityEventType.NEW_IP_LOGIN, request=request
        )
        user_keys.generate_user_keys(db, usuario)
    rate_limit.check_rate_limit("login-account", "ana@teste.dev", "5/minute")
    rate_limit.limit_by_ip("verify", "10/minute")(request)
    # O cliente do PDF já fala com o worker de verdade (REQ-62): aqui, o worker em memória.
    pdf = make_pdf()
    preparado = pdf_client.prepare_sign(pdf, page=1, x=10, y=10, seal_lines=["x"], signer_cert_pem=b"")
    assert pdf_client.finish_sign(preparado.prepared_pdf, b"cms").startswith(b"%PDF")
    assert pdf_client.verify(pdf).has_signature is False
