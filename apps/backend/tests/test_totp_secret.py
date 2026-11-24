"""REQ-12: segredo do TOTP com no mínimo 160 bits, armazenado cifrado."""

import base64
import uuid

import pytest
from sqlalchemy import text

from app.crypto.aead import DecryptionError
from app.db.models import User
from app.db.session import get_engine, get_sessionmaker
from app.services import totp_service


@pytest.fixture
def usuario(migrated_db):
    with get_sessionmaker()() as db:
        user = User(name="Ana", email=f"totp-{uuid.uuid4().hex[:8]}@teste.dev", password_hash="!")
        db.add(user)
        db.commit()
        db.refresh(user)
        db.expunge(user)
        return user


def test_segredo_tem_160_bits():
    segredo = totp_service.generate_secret()
    assert len(base64.b32decode(segredo)) * 8 >= 160


def test_segredos_sao_diferentes_a_cada_geracao():
    assert len({totp_service.generate_secret() for _ in range(50)}) == 50


def test_coluna_no_banco_nao_contem_o_segredo_em_claro(usuario):
    segredo = totp_service.generate_secret()
    with get_sessionmaker()() as db:
        user = db.get(User, usuario.id)
        totp_service.store_secret(user, segredo)
        db.commit()
    with get_engine().connect() as conexao:
        bruto = conexao.scalar(text("SELECT totp_secret_enc FROM users WHERE id = :id"), {"id": usuario.id})
    assert segredo.encode() not in bruto
    assert base64.b32decode(segredo) not in bruto
    with get_sessionmaker()() as db:
        assert totp_service.load_secret(db.get(User, usuario.id)) == segredo


def test_cifragem_usa_nonce_aleatorio(usuario):
    segredo = totp_service.generate_secret()
    totp_service.store_secret(usuario, segredo)
    primeiro = usuario.totp_secret_enc
    totp_service.store_secret(usuario, segredo)
    assert usuario.totp_secret_enc != primeiro


def test_segredo_cifrado_de_outra_conta_nao_decifra(usuario):
    totp_service.store_secret(usuario, totp_service.generate_secret())
    outra = User(id=uuid.uuid4(), name="Bia", email="bia@teste.dev", password_hash="!")
    outra.totp_secret_enc = usuario.totp_secret_enc
    with pytest.raises(DecryptionError):
        totp_service.load_secret(outra)


def test_sem_segredo_devolve_none(usuario):
    assert totp_service.load_secret(usuario) is None
