"""REQ-19: refresh token opaco de 256 bits, 7 dias, guardado como hash."""

import base64
import hashlib
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import Request, Response
from sqlalchemy import select

from app.db.models import RefreshToken, User
from app.db.session import get_sessionmaker
from app.services.token_service import hash_refresh_token, issue_tokens


@pytest.fixture
def emitido(migrated_db):
    request = Request({"type": "http", "headers": [(b"user-agent", b"pytest")], "client": ("127.0.0.1", 1)})
    with get_sessionmaker()() as db:
        user = User(name="Ana", email=f"rt-{uuid.uuid4().hex[:8]}@teste.dev", password_hash="!")
        db.add(user)
        db.flush()
        tokens = issue_tokens(db, user, request, Response())
        db.commit()
    return tokens


def _registro(token: str) -> RefreshToken:
    with get_sessionmaker()() as db:
        return db.scalar(select(RefreshToken).where(RefreshToken.token_sha256 == hash_refresh_token(token)))


def test_refresh_tem_256_bits_e_e_opaco(emitido):
    bruto = base64.urlsafe_b64decode(emitido.refresh_token + "=" * (-len(emitido.refresh_token) % 4))
    assert len(bruto) == 32
    assert emitido.refresh_token.count(".") == 0  # não é um JWT


def test_banco_guarda_so_o_hash(emitido):
    registro = _registro(emitido.refresh_token)
    assert registro is not None
    assert registro.token_sha256 == hashlib.sha256(emitido.refresh_token.encode()).hexdigest()
    assert emitido.refresh_token not in registro.token_sha256


def test_validade_de_7_dias(emitido):
    restante = _registro(emitido.refresh_token).expires_at - datetime.now(UTC)
    assert timedelta(days=7) - timedelta(minutes=1) < restante <= timedelta(days=7)


def test_tokens_diferentes_a_cada_emissao(migrated_db):
    request = Request({"type": "http", "headers": [], "client": ("127.0.0.1", 1)})
    with get_sessionmaker()() as db:
        user = User(name="Ana", email=f"rt-{uuid.uuid4().hex[:8]}@teste.dev", password_hash="!")
        db.add(user)
        db.flush()
        valores = {issue_tokens(db, user, request, Response()).refresh_token for _ in range(20)}
        db.rollback()
    assert len(valores) == 20


def test_refresh_nao_aparece_no_repr(emitido):
    assert emitido.refresh_token not in repr(emitido)
