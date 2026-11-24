"""REQ-56: todo registro de auditoria tem userId, timestamp UTC, IP, User-Agent, ação e resultado."""

import uuid
from datetime import UTC

import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from app.db.models import AuditLog
from app.db.session import get_engine, get_sessionmaker
from app.main import app
from app.services import audit_service as audit

A = audit.AuditAction
R = audit.AuditResult


def _request(ua: bytes = b"Mozilla/5.0", ip: str = "203.0.113.7") -> Request:
    return Request({"type": "http", "headers": [(b"user-agent", ua)], "client": (ip, 1)})


def _gravar(**kwargs) -> AuditLog:
    with get_sessionmaker()() as db:
        audit.record(db, **kwargs)
        db.commit()
        linha = db.scalar(select(AuditLog).order_by(AuditLog.id.desc()).limit(1))
        db.expunge(linha)
        return linha


# ------------------------------------------------------------------ os seis campos


def test_registro_tem_os_seis_campos(migrated_db):
    usuario = uuid.uuid4()
    linha = _gravar(action=A.LOGIN, result=R.SUCCESS, request=_request(), user_id=usuario)
    assert linha.user_id == usuario
    assert linha.ip == "203.0.113.7"
    assert linha.user_agent == "Mozilla/5.0"
    assert (linha.action, linha.result) == ("LOGIN", "SUCCESS")
    assert linha.occurred_at.utcoffset() is not None  # timestamptz: instante absoluto, lido em UTC


def test_horario_e_gravado_em_utc(migrated_db):
    linha = _gravar(action=A.LOGIN, result=R.SUCCESS, request=_request(), user_id=uuid.uuid4())
    with get_engine().connect() as conexao:
        conexao.execute(text("SET TIME ZONE 'America/Recife'"))
        utc = conexao.scalar(
            text("SELECT occurred_at AT TIME ZONE 'UTC' FROM audit_log WHERE id = :id"), {"id": linha.id}
        )
    assert utc == linha.occurred_at.astimezone(UTC).replace(tzinfo=None)


def test_sem_requisicao_ip_e_user_agent_ficam_desconhecidos(migrated_db):
    linha = _gravar(action=A.LOGIN, result=R.SUCCESS, request=None, user_id=uuid.uuid4())
    assert (linha.ip, linha.user_agent) == ("desconhecido", "desconhecido")


def test_user_agent_ausente_fica_desconhecido(migrated_db):
    linha = _gravar(action=A.LOGIN, result=R.SUCCESS, request=_request(ua=b""), user_id=uuid.uuid4())
    assert linha.user_agent == "desconhecido"


# ------------------------------------------------------------------ usuário nulo


def test_user_id_nulo_so_em_falha_de_autenticacao_ou_verificacao(migrated_db):
    for acao in audit.ANONYMOUS_ACTIONS:
        assert _gravar(action=acao, result=R.FAILURE, request=_request(), user_id=None).user_id is None


def test_servico_recusa_user_id_nulo_nas_demais_acoes(migrated_db):
    with get_sessionmaker()() as db, pytest.raises(ValueError, match="exige user_id"):
        audit.record(db, action=A.LOGIN, result=R.SUCCESS, request=_request(), user_id=None)


def test_falha_de_login_de_email_inexistente_tem_os_demais_campos(migrated_db):
    with get_sessionmaker()() as db:
        antes = db.scalar(select(AuditLog.id).order_by(AuditLog.id.desc()).limit(1)) or 0
    TestClient(app).post(
        "/api/v1/auth/login", json={"email": f"ninguem-{uuid.uuid4().hex}@teste.dev", "password": "x" * 12}
    )
    with get_sessionmaker()() as db:
        linha = db.scalar(select(AuditLog).where(AuditLog.id > antes, AuditLog.action == A.AUTH_FAILURE))
    assert linha.user_id is None
    assert linha.ip and linha.user_agent == "testclient" and linha.result == "FAILURE"


# ------------------------------------------------------------------ o banco também garante


@pytest.mark.parametrize(
    ("colunas", "valores"),
    [
        ("user_id, user_agent, action, result", "gen_random_uuid(), 'ua', 'LOGIN', 'SUCCESS'"),  # sem IP
        ("user_id, ip, action, result", "gen_random_uuid(), '1.2.3.4', 'LOGIN', 'SUCCESS'"),  # sem UA
        ("user_id, ip, user_agent, result", "gen_random_uuid(), '1.2.3.4', 'ua', 'SUCCESS'"),  # sem ação
        ("user_id, ip, user_agent, action", "gen_random_uuid(), '1.2.3.4', 'ua', 'LOGIN'"),  # sem resultado
        ("user_id, ip, user_agent, action, result", "gen_random_uuid(), '1.2.3.4', 'ua', '', 'SUCCESS'"),
        ("user_id, ip, user_agent, action, result", "gen_random_uuid(), '1.2.3.4', 'ua', 'LOGIN', 'TALVEZ'"),
        ("ip, user_agent, action, result", "'1.2.3.4', 'ua', 'LOGIN', 'SUCCESS'"),  # sem usuário
    ],
    ids=["sem-ip", "sem-ua", "sem-acao", "sem-resultado", "acao-vazia", "resultado-invalido", "sem-usuario"],
)
def test_insercao_direta_incompleta_e_recusada(migrated_db, colunas, valores):
    with get_engine().connect() as conexao:
        with pytest.raises(IntegrityError):
            conexao.execute(text(f"INSERT INTO audit_log ({colunas}) VALUES ({valores})"))  # noqa: S608
        conexao.rollback()


# ------------------------------------------------------------------ details sem dados sensíveis


def test_details_nao_guarda_segredos_nem_conteudo_binario(migrated_db):
    linha = _gravar(
        action=A.DOCUMENT_SIGNED,
        result=R.SUCCESS,
        request=_request(),
        user_id=uuid.uuid4(),
        details={
            "signature_id": "abc",
            "password": "Senha-Forte#2026",
            "refresh_token": "xyz",
            "recovery_code": "1234-5678",
            "arquivo": b"%PDF-1.7",
            "extra": {"privateKey": "-----BEGIN", "page": 1},
        },
    )
    assert linha.details == {
        "signature_id": "abc",
        "password": "[removido]",
        "refresh_token": "[removido]",
        "recovery_code": "[removido]",
        "arquivo": "[removido]",
        "extra": {"privateKey": "[removido]", "page": 1},
    }
