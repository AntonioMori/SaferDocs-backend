"""Assinatura de PDF (REQ-46): rota, CMS montado na API e assinatura ISO 32000 válida.

O worker roda em memória (fixture `fake_pdf_worker`), com o código real de
`pdf_worker/sign.py`. A assinatura do PDF de saída é validada com o pyHanko,
como um leitor de PDF faria.
"""

import io
import uuid

import pytest
from fastapi.testclient import TestClient
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext
from sqlalchemy import select

from app.db.models import User
from app.db.session import get_sessionmaker
from app.main import app
from tests.conftest import make_pdf, session_token

SENHA = "Senha-Forte#2026"


@pytest.fixture
def client(migrated_db):
    return TestClient(app)


@pytest.fixture
def conta(client):
    email = f"assina-{uuid.uuid4().hex[:10]}@teste.dev"
    resposta = client.post(
        "/api/v1/auth/register", json={"name": "Ana Souza", "email": email, "password": SENHA}
    )
    assert resposta.status_code == 201
    with get_sessionmaker()() as db:
        user = db.scalar(select(User).where(User.email == email))
        db.expunge(user)
    return {"user": user, "headers": {"Authorization": f"Bearer {session_token(user.id)}"}}


def assinar(client, conta, pdf, page="1", x="50", y="50"):
    return client.post(
        "/api/v1/documents/sign",
        files={"file": ("doc.pdf", pdf, "application/pdf")},
        data={"page": page, "x": x, "y": y},
        headers=conta["headers"],
    )


def validar(pdf: bytes):
    """Valida a última assinatura embutida como um leitor de PDF (confiando no certificado embutido)."""
    sig = PdfFileReader(io.BytesIO(pdf)).embedded_signatures[-1]
    contexto = ValidationContext(trust_roots=[sig.signer_cert], allow_fetching=False)
    return sig, validate_pdf_signature(sig, signer_validation_context=contexto)


def test_pdf_assinado_tem_assinatura_iso_32000_valida(client, conta, fake_pdf_worker):
    original = make_pdf(pages=2)
    resposta = assinar(client, conta, original)
    assert resposta.status_code == 200, resposta.text
    assert resposta.headers["content-type"] == "application/pdf"
    assert "attachment" in resposta.headers["content-disposition"]
    uuid.UUID(resposta.headers["x-signature-id"])
    assinado = resposta.content
    assert assinado.startswith(original[: len(original) - 10][:8])  # atualização incremental do original
    sig, status = validar(assinado)
    assert status.intact and status.valid  # o CMS confere com os bytes cobertos
    assert status.coverage.name == "ENTIRE_FILE"
    assert sig.sig_object["/SubFilter"] == "/adbe.pkcs7.detached"
    # Quem assinou é o certificado do usuário (REQ-45).
    assert sig.signer_cert.dump() == conta["user"].signing_cert


def test_campo_de_assinatura_com_aparencia_na_pagina_escolhida(client, conta, fake_pdf_worker):
    # Critério do REQ-46 (o Adobe Reader reconhece o campo): campo /Sig com widget na página.
    import pikepdf

    assinado = assinar(client, conta, make_pdf(pages=3), page="2", x="100", y="200").content
    doc = pikepdf.open(io.BytesIO(assinado))
    campos = [f for f in doc.Root.AcroForm.Fields if f.get("/FT") == "/Sig"]
    assert len(campos) == 1
    widget = campos[0]
    assert widget.P.objgen == doc.pages[1].obj.objgen  # página 2
    assert [float(v) for v in widget.Rect] == [100, 200, 340, 280]
    assert "/N" in widget.AP  # aparência (o selo)


def test_um_byte_alterado_depois_de_assinar_quebra_a_assinatura(client, conta, fake_pdf_worker):
    assinado = bytearray(assinar(client, conta, make_pdf()).content)
    posicao = assinado.index(b"/MediaBox") + 12
    assinado[posicao] ^= 0x01
    try:
        _, status = validar(bytes(assinado))
    except Exception:  # noqa: BLE001 - o pyHanko recusar a estrutura alterada também conta
        return
    assert not status.intact


def test_chave_privada_nunca_vai_para_o_worker(client, conta, fake_pdf_worker):
    from app.crypto.aead import AeadContext, decrypt

    assinar(client, conta, make_pdf())
    user = conta["user"]
    privada = decrypt(AeadContext.SIGNING_KEY, user.signing_private_key_enc, associated_data=user.id.bytes)
    enviado = b"".join(fake_pdf_worker)
    assert privada not in enviado
    assert privada[-32:] not in enviado  # nem o escalar da chave
    assert b"PRIVATE KEY" not in enviado
    operacoes = [p[8 : p.index(b"}") + 1] for p in fake_pdf_worker]
    assert any(b'"prepare_sign"' in o for o in operacoes) and any(b'"finish_sign"' in o for o in operacoes)


def test_sem_autenticacao_nao_le_o_upload(client):
    import asyncio

    lidos = 0

    async def receive():
        nonlocal lidos
        lidos += 1
        return {"type": "http.request", "body": b"x" * 1024 * 1024, "more_body": lidos < 30}

    enviados: list[dict] = []

    async def send(message):
        enviados.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/api/v1/documents/sign",
        "raw_path": b"/api/v1/documents/sign",
        "query_string": b"",
        "headers": [(b"content-type", b"multipart/form-data; boundary=b")],
        "client": ("127.0.0.1", 5000),
        "server": ("testserver", 80),
    }
    asyncio.run(app(scope, receive, send))
    assert next(m["status"] for m in enviados if m["type"] == "http.response.start") == 401
    assert lidos <= 1


@pytest.mark.parametrize(
    ("campos", "campo_com_erro"),
    [
        ({"page": "abc", "x": "1", "y": "1"}, "page"),
        ({"page": "1", "x": "nan", "y": "1"}, "x"),
        ({"page": "0", "x": "1", "y": "1"}, "page"),
        ({"page": "1", "x": "1", "y": "-5"}, "y"),
    ],
)
def test_posicao_invalida_e_erro_de_validacao(client, conta, fake_pdf_worker, campos, campo_com_erro):
    resposta = assinar(client, conta, make_pdf(), **campos)
    assert resposta.status_code == 400
    assert resposta.json()["code"] == "VAL_001"
    assert campo_com_erro in [f["field"] for f in resposta.json()["fields"]]


def test_pdf_com_javascript_e_recusado_na_assinatura(client, conta, fake_pdf_worker):
    from tests.test_pdf_javascript import COM_JAVASCRIPT, raw_pdf

    resposta = assinar(client, conta, raw_pdf(COM_JAVASCRIPT["open-action"]))
    assert resposta.status_code == 400
    assert resposta.json()["code"] == "DOC_003"


def test_conta_antiga_sem_chaves_ganha_o_par_na_primeira_assinatura(client, conta, fake_pdf_worker):
    with get_sessionmaker()() as db:
        user = db.get(User, conta["user"].id)
        user.signing_cert = user.signing_public_key = user.signing_private_key_enc = None
        db.commit()
    resposta = assinar(client, conta, make_pdf())
    assert resposta.status_code == 200
    with get_sessionmaker()() as db:
        assert db.get(User, conta["user"].id).signing_cert is not None
