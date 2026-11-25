"""Comparação dos hashes (REQ-51): o arquivo enviado contra o registrado na assinatura."""

import uuid

import pytest
from fastapi.testclient import TestClient

from app.db.session import get_sessionmaker
from app.main import app
from app.pdf import client as pdf_client
from app.services.verify_service import find_registered_signature, sha256_hex
from tests.conftest import make_pdf, session_token

SENHA = "Senha-Forte#2026"


@pytest.fixture
def assinado(migrated_db, fake_pdf_worker):
    client = TestClient(app)
    email = f"hash-{uuid.uuid4().hex[:10]}@teste.dev"
    user_id = client.post(
        "/api/v1/auth/register", json={"name": "Ana", "email": email, "password": SENHA}
    ).json()["id"]
    resposta = client.post(
        "/api/v1/documents/sign",
        files={"file": ("d.pdf", make_pdf(), "application/pdf")},
        data={"page": "1", "x": "10", "y": "10"},
        headers={"Authorization": f"Bearer {session_token(uuid.UUID(user_id))}"},
    )
    assert resposta.status_code == 200
    return resposta.content, uuid.UUID(resposta.headers["x-signature-id"])


def test_arquivo_assinado_intacto_bate_com_o_registro(assinado):
    # Critério de aceite do REQ-51.
    pdf, signature_id = assinado
    chave = pdf_client.verify(pdf).signer_public_key_der
    with get_sessionmaker()() as db:
        registro = find_registered_signature(db, sha256_hex(pdf), chave)
        assert registro is not None and registro.id == signature_id


def test_hash_diferente_nao_bate(assinado):
    pdf, _ = assinado
    chave = pdf_client.verify(pdf).signer_public_key_der
    with get_sessionmaker()() as db:
        assert find_registered_signature(db, sha256_hex(pdf + b"\n"), chave) is None


def test_mesmo_hash_com_outra_chave_nao_bate(assinado):
    from tests.conftest import make_signer

    pdf, _ = assinado
    outra_chave = make_signer()[0].signing_public_key
    with get_sessionmaker()() as db:
        assert find_registered_signature(db, sha256_hex(pdf), outra_chave) is None
        assert find_registered_signature(db, sha256_hex(pdf), None) is None
