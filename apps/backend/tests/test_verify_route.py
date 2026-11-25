"""Verificação pública (REQ-52 a 54): os três resultados, rate limit e descarte do PDF."""

import io
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db.models import AuditLog
from app.db.session import get_sessionmaker
from app.main import app
from tests.conftest import make_pdf, session_token

SENHA = "Senha-Forte#2026"


@pytest.fixture
def client(migrated_db):
    return TestClient(app)


@pytest.fixture
def assinado(client, fake_pdf_worker):
    email = f"verifica-{uuid.uuid4().hex[:10]}@teste.dev"
    user_id = client.post(
        "/api/v1/auth/register", json={"name": "Carla Dias", "email": email, "password": SENHA}
    ).json()["id"]
    resposta = client.post(
        "/api/v1/documents/sign",
        files={"file": ("d.pdf", make_pdf(), "application/pdf")},
        data={"page": "1", "x": "10", "y": "10"},
        headers={"Authorization": f"Bearer {session_token(uuid.UUID(user_id))}"},
    )
    assert resposta.status_code == 200
    return resposta.content, resposta.headers["x-signature-id"]


def verificar(client, pdf: bytes, **kwargs):
    return client.post("/api/v1/verify", files={"file": ("d.pdf", pdf, "application/pdf")}, **kwargs)


# --------------------------------------------------------------- os três resultados (critério do REQ-52)


def test_documento_integro(client, assinado):
    pdf, signature_id = assinado
    resposta = verificar(client, pdf)
    assert resposta.status_code == 200
    corpo = resposta.json()
    assert corpo["status"] == "INTEGRO"
    assert corpo["signer_name"] == "Carla Dias"
    assert corpo["signature_id"] == signature_id
    assert corpo["signed_at"]


def test_documento_adulterado_por_um_byte(client, assinado):
    pdf, _ = assinado
    alterado = bytearray(pdf)
    alterado[alterado.index(b"/MediaBox") + 12] ^= 0x01
    corpo = verificar(client, bytes(alterado)).json()
    assert corpo == {"status": "ADULTERADO", "signer_name": None, "signed_at": None, "signature_id": None}


def test_assinatura_nao_encontrada(client, fake_pdf_worker):
    corpo = verificar(client, make_pdf()).json()
    assert corpo["status"] == "NAO_ENCONTRADA"
    assert corpo["signer_name"] is None


# --------------------------------------------------------------- outros caminhos para ADULTERADO


def test_revisao_acrescentada_depois_de_assinar_e_adulterado(client, assinado):
    from pyhanko.pdf_utils.generic import NameObject, NumberObject
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

    pdf, _ = assinado
    escritor = IncrementalPdfFileWriter(io.BytesIO(pdf))
    pagina = escritor.root["/Pages"]["/Kids"][0].get_object()
    pagina[NameObject("/Rotate")] = NumberObject(90)
    escritor.update_container(pagina)
    saida = io.BytesIO()
    escritor.write(saida)
    assert verificar(client, saida.getvalue()).json()["status"] == "ADULTERADO"


def test_assinatura_valida_mas_sem_registro_e_adulterado(client, fake_pdf_worker):
    # Assinado corretamente por alguém de fora do sistema: o hash não está registrado.
    from tests.test_pdf_verify import assinar

    pdf, _ = assinar(make_pdf())
    assert verificar(client, pdf).json()["status"] == "ADULTERADO"


def test_documento_assinado_e_depois_reassinado_por_outro_e_adulterado(client, assinado, fake_pdf_worker):
    # O registro é do arquivo assinado pela Carla; reassinar com outra chave muda o arquivo.
    from tests.test_pdf_verify import assinar

    pdf, _ = assinado
    reassinado, _ = assinar(pdf)
    assert verificar(client, reassinado).json()["status"] == "ADULTERADO"


# --------------------------------------------------------------- entrada e auditoria


def test_verificacao_e_publica(client, fake_pdf_worker):
    assert verificar(client, make_pdf()).status_code == 200  # sem Authorization


def test_arquivo_que_nao_e_pdf_ou_tem_javascript(client, fake_pdf_worker):
    from tests.test_pdf_javascript import COM_JAVASCRIPT, raw_pdf

    assert verificar(client, b"MZ\x90\x00 executavel").json()["code"] == "DOC_001"
    assert verificar(client, raw_pdf(COM_JAVASCRIPT["open-action"])).json()["code"] == "DOC_003"


def test_toda_verificacao_vai_para_a_auditoria_sem_usuario(client, assinado):
    pdf, signature_id = assinado
    verificar(client, pdf)
    verificar(client, make_pdf())
    with get_sessionmaker()() as db:
        registros = db.scalars(
            select(AuditLog)
            .where(AuditLog.action == "DOCUMENT_VERIFIED")
            .order_by(AuditLog.id.desc())
            .limit(2)
        ).all()
    assert [r.details for r in reversed(registros)] == [
        {"status": "INTEGRO", "signature_id": signature_id},
        {"status": "NAO_ENCONTRADA"},
    ]
    assert all(r.user_id is None and r.result == "SUCCESS" for r in registros)
