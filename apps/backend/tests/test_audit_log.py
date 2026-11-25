"""REQ-55: log de auditoria append-only com os sete eventos obrigatórios."""

import uuid

import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from app.db.models import AuditLog
from app.db.session import get_engine, get_sessionmaker
from app.main import app
from app.services import audit_service as audit

SENHA = "Senha-Forte#2026"
NOVA = "Outra-Senha#2027"
A = audit.AuditAction


@pytest.fixture
def client(migrated_db):
    return TestClient(app, headers={"Origin": "http://localhost:3039"})  # o front manda Origin (REQ-65)


def _acoes(user_id) -> list[str]:
    with get_sessionmaker()() as db:
        return list(
            db.scalars(
                select(AuditLog.action)
                .where(AuditLog.user_id == uuid.UUID(str(user_id)))
                .order_by(AuditLog.id)
            )
        )


def _registro_qualquer() -> int:
    request = Request({"type": "http", "headers": [(b"user-agent", b"pytest")], "client": ("10.0.0.1", 1)})
    with get_sessionmaker()() as db:
        audit.record(
            db, action=A.LOGIN, result=audit.AuditResult.SUCCESS, request=request, user_id=uuid.uuid4()
        )
        db.commit()
        return db.scalar(select(AuditLog.id).order_by(AuditLog.id.desc()).limit(1))


# ------------------------------------------------------------------ imutabilidade


@pytest.mark.parametrize(
    "comando",
    [
        "UPDATE audit_log SET result = 'FAILURE' WHERE id = :id",
        "DELETE FROM audit_log WHERE id = :id",
        "TRUNCATE audit_log",
    ],
    ids=["update", "delete", "truncate"],
)
def test_alteracao_direta_no_banco_falha_ate_para_o_dono(migrated_db, comando):
    registro = _registro_qualquer()
    with get_engine().connect() as conexao:
        with pytest.raises(DBAPIError, match="append-only"):
            conexao.execute(text(comando), {"id": registro})
        conexao.rollback()
    with get_engine().connect() as conexao:
        assert (
            conexao.scalar(text("SELECT result FROM audit_log WHERE id = :id"), {"id": registro}) == "SUCCESS"
        )


@pytest.mark.parametrize(
    "comando",
    ["UPDATE audit_log SET result = 'FAILURE' WHERE id = :id", "DELETE FROM audit_log WHERE id = :id"],
    ids=["update", "delete"],
)
def test_papel_da_aplicacao_nao_tem_permissao_de_alterar(migrated_db, comando):
    registro = _registro_qualquer()
    with get_engine().connect() as conexao:
        conexao.execute(text("SET ROLE saferdocs_app"))
        with pytest.raises(DBAPIError, match="permission denied"):
            conexao.execute(text(comando), {"id": registro})
        conexao.rollback()


def test_papel_da_aplicacao_pode_ler_e_inserir(migrated_db):
    with get_engine().connect() as conexao:
        conexao.execute(text("SET ROLE saferdocs_app"))
        conexao.execute(
            text(
                "INSERT INTO audit_log (user_id, ip, user_agent, action, result) "
                "VALUES (gen_random_uuid(), '1.2.3.4', 'ua', 'LOGIN', 'SUCCESS')"
            )
        )
        assert conexao.scalar(text("SELECT count(*) FROM audit_log")) >= 1
        assert conexao.scalar(text("SELECT count(*) FROM users")) >= 0  # demais tabelas seguem acessíveis
        conexao.rollback()


# ------------------------------------------------------------------ eventos registrados


def test_registro_guarda_origem_da_requisicao(migrated_db):
    registro = _registro_qualquer()
    with get_sessionmaker()() as db:
        linha = db.get(AuditLog, registro)
        assert (linha.ip, linha.user_agent, linha.action, linha.result) == (
            "10.0.0.1",
            "pytest",
            "LOGIN",
            "SUCCESS",
        )
        assert linha.occurred_at.utcoffset() is not None


def test_registro_some_se_a_operacao_for_desfeita(migrated_db):
    usuario = uuid.uuid4()
    with get_sessionmaker()() as db:
        audit.record(db, action=A.LOGIN, result=audit.AuditResult.SUCCESS, request=None, user_id=usuario)
        db.rollback()
    assert _acoes(usuario) == []


def test_fluxo_de_conta_registra_os_eventos_do_lado_a(client):
    email = f"audit-{uuid.uuid4().hex[:10]}@teste.dev"
    user_id = client.post(
        "/api/v1/auth/register", json={"name": "Ana", "email": email, "password": SENHA}
    ).json()["id"]

    assert client.post("/api/v1/auth/login", json={"email": email, "password": "errada"}).status_code == 401
    token = client.post("/api/v1/auth/login", json={"email": email, "password": SENHA}).json()["access_token"]
    novo = client.put(
        "/api/v1/auth/password",
        json={"current_password": SENHA, "new_password": NOVA},
        headers={"Authorization": f"Bearer {token}"},
    ).json()["access_token"]
    assert client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {novo}"}).status_code == 204

    acoes = _acoes(user_id)
    for esperada in (A.AUTH_FAILURE, A.LOGIN, A.TOKEN_ISSUED, A.PASSWORD_CHANGED, A.LOGOUT):
        assert esperada in acoes
    assert (
        acoes.index(A.AUTH_FAILURE)
        < acoes.index(A.LOGIN)
        < acoes.index(A.PASSWORD_CHANGED)
        < acoes.index(A.LOGOUT)
    )


def test_falha_de_login_de_email_inexistente_tambem_e_registrada(client):
    with get_sessionmaker()() as db:
        antes = db.scalar(select(AuditLog.id).order_by(AuditLog.id.desc()).limit(1)) or 0
    client.post(
        "/api/v1/auth/login", json={"email": f"ninguem-{uuid.uuid4().hex}@teste.dev", "password": SENHA}
    )
    with get_sessionmaker()() as db:
        novos = db.scalars(
            select(AuditLog).where(AuditLog.id > antes, AuditLog.action == A.AUTH_FAILURE)
        ).all()
    assert any(r.user_id is None and r.result == "FAILURE" for r in novos)


@pytest.mark.parametrize("acao", [A.DOCUMENT_SIGNED, A.DOCUMENT_VERIFIED])
def test_eventos_do_lado_b_sao_gravados_pelo_mesmo_servico(migrated_db, acao):
    usuario = uuid.uuid4()
    with get_sessionmaker()() as db:
        audit.record(db, action=acao, result=audit.AuditResult.SUCCESS, request=None, user_id=usuario)
        db.commit()
    assert _acoes(usuario) == [acao]
