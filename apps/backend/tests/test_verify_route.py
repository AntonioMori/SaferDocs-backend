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


# --------------------------------------------------------------- rate limit (REQ-53)


def test_excesso_de_verificacoes_por_ip_recebe_429(client, fake_pdf_worker, monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "rate_limit_verify_per_ip", "3/minute")
    respostas = [verificar(client, make_pdf()) for _ in range(4)]
    assert [r.status_code for r in respostas] == [200, 200, 200, 429]
    assert respostas[3].json()["code"] == "RATE_001"
    assert int(respostas[3].headers["retry-after"]) >= 1


def test_rate_limit_da_verificacao_barra_antes_de_ler_o_upload(client, monkeypatch):
    import asyncio

    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "rate_limit_verify_per_ip", "1/minute")
    from app.middlewares.rate_limit import check_rate_limit

    check_rate_limit("verify", "127.0.0.1", "1/minute")  # gasta a única vaga do IP
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
        "path": "/api/v1/verify",
        "raw_path": b"/api/v1/verify",
        "query_string": b"",
        "headers": [(b"content-type", b"multipart/form-data; boundary=b")],
        "client": ("127.0.0.1", 5000),
        "server": ("testserver", 80),
    }
    asyncio.run(app(scope, receive, send))
    assert next(m["status"] for m in enviados if m["type"] == "http.response.start") == 429
    assert lidos <= 1


def test_limite_da_verificacao_nao_divide_vaga_com_o_login(client, fake_pdf_worker, monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "rate_limit_verify_per_ip", "1/minute")
    monkeypatch.setattr(get_settings(), "rate_limit_login_per_ip", "1/minute")
    client.post("/api/v1/auth/login", json={"email": "a@teste.dev", "password": "x"})
    assert verificar(client, make_pdf()).status_code == 200


# --------------------------------------------------------------- PDF descartado (REQ-54)


def _pdf_com_marca(marca: bytes) -> bytes:
    from tests.test_pdf_javascript import raw_pdf, stream

    return raw_pdf(
        {
            3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R >>",
            4: stream(b"BT /F1 10 Tf 20 20 Td (" + marca + b") Tj ET"),
        }
    )


def test_nenhum_arquivo_e_gravado_durante_a_verificacao(client, fake_pdf_worker, monkeypatch):
    # Critério de aceite: nenhum arquivo aparece em disco durante a verificação.
    import builtins
    import tempfile

    abrir = builtins.open

    def so_leitura(arquivo, mode="r", *args, **kwargs):
        if any(m in mode for m in "wax+"):
            raise AssertionError(f"tentou gravar {arquivo!r} durante a verificação")
        return abrir(arquivo, mode, *args, **kwargs)

    def proibido(*args, **kwargs):
        raise AssertionError("tentou criar arquivo temporário durante a verificação")

    pdf = _pdf_com_marca(b"MARCA-DISCO")
    monkeypatch.setattr(builtins, "open", so_leitura)
    for nome in ("SpooledTemporaryFile", "TemporaryFile", "NamedTemporaryFile", "mkstemp"):
        monkeypatch.setattr(tempfile, nome, proibido)
    assert verificar(client, pdf).json()["status"] == "NAO_ENCONTRADA"


def test_pdf_verificado_nao_fica_no_banco_nem_no_log(client, fake_pdf_worker, caplog):
    import logging

    from sqlalchemy import text

    marca = f"MARCA-{uuid.uuid4().hex}".encode()
    with caplog.at_level(logging.DEBUG):
        assert verificar(client, _pdf_com_marca(marca)).status_code == 200
    assert marca.decode() not in caplog.text
    with get_sessionmaker()() as db:
        tabelas = db.execute(
            text("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'")
        ).scalars()
        for tabela in tabelas:
            achou = db.execute(
                text(f'SELECT count(*) FROM "{tabela}" t WHERE position(:m in t::text) > 0'),  # noqa: S608
                {"m": marca.decode()},
            ).scalar()
            assert achou == 0, tabela
