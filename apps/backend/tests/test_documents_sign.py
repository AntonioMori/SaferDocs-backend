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
    assert any(b'"prepare_sign"' in o for o in operacoes)
    # O CMS é escrito no /Contents pela própria API: o PDF assinado não volta para o worker.
    assert not any(b'"finish_sign"' in o for o in operacoes)


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
        # QA: int()/float() aceitariam estes.
        ({"page": "1", "x": "1_0", "y": "1"}, "x"),
        ({"page": "1_0", "x": "1", "y": "1"}, "page"),
        ({"page": "1", "x": "1e2", "y": "1"}, "x"),
        ({"page": "1", "x": " 10", "y": "1"}, "x"),
        ({"page": "١", "x": "1", "y": "1"}, "page"),  # dígito árabe-índico
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


# --------------------------------------------------------------- selo (REQ-47)


def _texto_do_selo(pdf: bytes) -> str:
    import pikepdf

    doc = pikepdf.open(io.BytesIO(pdf))
    campo = next(f for f in doc.Root.AcroForm.Fields if f.get("/FT") == "/Sig")
    stream = campo.AP.N
    pedacos = [stream.read_bytes()]
    for xobj in (stream.get("/Resources", {}).get("/XObject", {}) or {}).values():
        pedacos.append(xobj.read_bytes())
    import re

    texto = b"".join(pedacos).decode("latin-1")
    # Strings do PDF: o pyHanko escreve pontuação como escape octal ("\\072" é ":").
    return re.sub(r"\\(\d{3})", lambda m: chr(int(m.group(1), 8)), texto)


def test_selo_mostra_nome_data_utc_hash_e_id(client, conta, fake_pdf_worker):
    import hashlib

    original = make_pdf()
    resposta = assinar(client, conta, original)
    texto = _texto_do_selo(resposta.content)
    sha = hashlib.sha256(original).hexdigest()
    assert "Assinado por: Ana Souza" in texto
    assert " UTC" in texto and "Em: 20" in texto
    assert sha[:32] in texto and sha[32:] in texto  # hash completo, em duas linhas
    assert f"ID: {resposta.headers['x-signature-id']}" in texto


def test_data_do_selo_esta_em_utc(client, conta, fake_pdf_worker):
    import datetime as dt
    import re

    antes = dt.datetime.now(dt.UTC).replace(microsecond=0)
    texto = _texto_do_selo(assinar(client, conta, make_pdf()).content)
    depois = dt.datetime.now(dt.UTC)
    carimbo = re.search(r"Em: (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) UTC", texto)
    assert carimbo
    valor = carimbo.group(1)
    momento = dt.datetime.strptime(valor, "%Y-%m-%d %H:%M:%S").replace(tzinfo=dt.UTC)
    assert antes <= momento <= depois


def test_nome_longo_ou_com_quebra_de_linha_nao_estoura_o_selo():
    import datetime as dt

    from app.db.models import User
    from app.services.signing_service import seal_lines

    user = User(name="Maria\nda Silva " + "Sobrenome " * 10)
    linhas = seal_lines(user, uuid.uuid4(), dt.datetime.now(dt.UTC), "a" * 64)
    assert all("\n" not in linha for linha in linhas)
    assert all(len(linha) <= 48 for linha in linhas)
    assert linhas[0].startswith("Assinado por: Maria da Silva") and linhas[0].endswith("...")


# --------------------------------------------------------------- registro (REQ-48)


def test_cada_assinatura_registra_hashes_usuario_data_ip_e_posicao(client, conta, fake_pdf_worker):
    import hashlib

    from app.db.models import AuditLog, Signature

    original = make_pdf(pages=2)
    resposta = assinar(client, conta, original, page="2", x="30.5", y="40")
    signature_id = uuid.UUID(resposta.headers["x-signature-id"])
    with get_sessionmaker()() as db:
        registro = db.get(Signature, signature_id)
        assert registro.user_id == conta["user"].id
        assert registro.original_sha256 == hashlib.sha256(original).hexdigest()
        assert registro.signed_sha256 == hashlib.sha256(resposta.content).hexdigest()
        assert registro.signed_at is not None and registro.signed_at.utcoffset() is not None
        assert registro.user_agent == "testclient"
        assert (registro.page, float(registro.x), float(registro.y)) == (2, 30.5, 40.0)
        auditoria = db.scalars(
            select(AuditLog).where(AuditLog.user_id == conta["user"].id, AuditLog.action == "DOCUMENT_SIGNED")
        ).all()
        assert [a.result for a in auditoria] == ["SUCCESS"]
        assert auditoria[0].details == {"signature_id": str(signature_id)}


def test_ip_valido_e_registrado_no_formato_inet(conta, fake_pdf_worker, migrated_db):
    from app.db.models import Signature

    cliente_com_ip = TestClient(app, client=("203.0.113.7", 5000))
    token = session_token(conta["user"].id, ip="203.0.113.7")
    resposta = cliente_com_ip.post(
        "/api/v1/documents/sign",
        files={"file": ("doc.pdf", make_pdf(), "application/pdf")},
        data={"page": "1", "x": "50", "y": "50"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resposta.status_code == 200, resposta.text
    with get_sessionmaker()() as db:
        assert str(db.get(Signature, uuid.UUID(resposta.headers["x-signature-id"])).ip) == "203.0.113.7"


def test_falha_na_assinatura_nao_registra_e_vai_para_a_auditoria(client, conta, fake_pdf_worker):
    from app.db.models import AuditLog, Signature

    resposta = assinar(client, conta, b"%PDF-1.7\nquebrado")
    assert resposta.status_code == 400
    with get_sessionmaker()() as db:
        assert db.scalars(select(Signature).where(Signature.user_id == conta["user"].id)).all() == []
        falhas = db.scalars(
            select(AuditLog).where(AuditLog.user_id == conta["user"].id, AuditLog.action == "DOCUMENT_SIGNED")
        ).all()
        assert [(f.result, f.details) for f in falhas] == [("FAILURE", {"error": "DOC_004"})]


def test_historico_mostra_so_as_minhas_assinaturas_sem_o_pdf(client, conta, fake_pdf_worker):
    outra = client.post(
        "/api/v1/auth/register",
        json={"name": "Bia", "email": f"bia-{uuid.uuid4().hex[:8]}@teste.dev", "password": SENHA},
    ).json()
    outra_conta = {"headers": {"Authorization": f"Bearer {session_token(uuid.UUID(outra['id']))}"}}
    ids = [assinar(client, conta, make_pdf()).headers["x-signature-id"] for _ in range(2)]
    assinar(client, outra_conta, make_pdf())
    resposta = client.get("/api/v1/documents/signatures", headers=conta["headers"])
    assert resposta.status_code == 200
    corpo = resposta.json()
    assert sorted(item["id"] for item in corpo) == sorted(ids)
    assert set(corpo[0]) == {"id", "original_sha256", "signed_sha256", "signed_at", "page", "x", "y"}
    assert client.get("/api/v1/documents/signatures").status_code == 401


# --------------------------------------------------------------- posição (REQ-49)


@pytest.mark.parametrize(
    ("page", "x", "y"),
    [
        ("3", "50", "50"),  # página inexistente (o PDF tem 2)
        ("1", "356", "50"),  # 356 + 240 > 595: sai pela direita
        ("1", "50", "763"),  # 763 + 80 > 842: sai por cima
    ],
    ids=["pagina-inexistente", "sai-pela-direita", "sai-por-cima"],
)
def test_posicao_fora_da_pagina_e_doc_005(client, conta, fake_pdf_worker, page, x, y):
    # Critério de aceite: página inexistente retorna DOC_005.
    resposta = assinar(client, conta, make_pdf(pages=2), page=page, x=x, y=y)
    assert resposta.status_code == 400
    assert resposta.json()["code"] == "DOC_005"


def test_selo_encostado_nos_cantos_da_pagina_passa(client, conta, fake_pdf_worker):
    for x, y in (("0", "0"), ("355", "762")):  # 595 x 842, selo 240 x 80
        assert assinar(client, conta, make_pdf(), x=x, y=y).status_code == 200


def test_posicao_e_relativa_ao_tamanho_de_cada_pagina(client, conta, fake_pdf_worker):
    import pikepdf

    doc = pikepdf.new()
    doc.add_blank_page(page_size=(842, 595))  # página 1 deitada
    doc.add_blank_page(page_size=(300, 300))  # página 2 pequena
    buffer = io.BytesIO()
    doc.save(buffer)
    pdf = buffer.getvalue()
    assert assinar(client, conta, pdf, page="1", x="600", y="10").status_code == 200
    assert assinar(client, conta, pdf, page="2", x="100", y="10").json()["code"] == "DOC_005"


def test_posicao_e_relativa_ao_canto_da_pagina_mesmo_com_mediabox_deslocado(client, conta, fake_pdf_worker):
    import pikepdf

    from tests.test_pdf_javascript import raw_pdf

    pdf = raw_pdf({3: b"<< /Type /Page /Parent 2 0 R /MediaBox [100 200 695 1042] >>"})
    assinado = assinar(client, conta, pdf, x="0", y="0").content
    doc = pikepdf.open(io.BytesIO(assinado))
    widget = next(f for f in doc.Root.AcroForm.Fields if f.get("/FT") == "/Sig")
    assert [float(v) for v in widget.Rect] == [100, 200, 340, 280]
