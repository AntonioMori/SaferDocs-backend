"""Leitura do upload de PDF: tamanho máximo (REQ-61), formato e campos."""

from typing import Annotated

import pytest
from fastapi import APIRouter, Depends
from fastapi.testclient import TestClient

from app.main import create_app
from app.pdf.upload import MULTIPART_OVERHEAD_BYTES, PdfUpload, pdf_upload_with

MB = 1024 * 1024
PDF = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"

router = APIRouter()


@router.post("/_teste/upload")
async def upload(arquivo: Annotated[PdfUpload, Depends(pdf_upload_with())]):
    return {"size": len(arquivo.pdf), "fields": arquivo.fields}


@router.post("/_teste/upload-campos")
async def upload_campos(arquivo: Annotated[PdfUpload, Depends(pdf_upload_with("page", "x"))]):
    return {"size": len(arquivo.pdf), "fields": arquivo.fields}


test_app = create_app()
test_app.include_router(router)
client = TestClient(test_app)


def _multipart(
    parts: list[tuple[str, bytes, str | None]], boundary: str = "qa-boundary"
) -> tuple[bytes, str]:
    """Monta um corpo multipart à mão: (nome, conteúdo, filename ou None)."""
    body = bytearray()
    for name, content, filename in parts:
        body += f"--{boundary}\r\n".encode()
        disposition = f'form-data; name="{name}"'
        if filename is not None:
            disposition += f'; filename="{filename}"'
        body += f"Content-Disposition: {disposition}\r\n".encode()
        if filename is not None:
            body += b"Content-Type: application/pdf\r\n"
        body += b"\r\n" + content + b"\r\n"
    body += f"--{boundary}--\r\n".encode()
    return bytes(body), f"multipart/form-data; boundary={boundary}"


def _post(path: str, parts, **kwargs):
    body, content_type = _multipart(parts)
    return client.post(path, content=body, headers={"Content-Type": content_type}, **kwargs)


# --------------------------------------------------------------- caminho feliz


def test_pdf_pequeno_e_lido_inteiro_em_memoria():
    response = _post("/_teste/upload", [("file", PDF, "a.pdf")])
    assert response.status_code == 200
    assert response.json() == {"size": len(PDF), "fields": {}}


def test_campos_de_texto_declarados_chegam_na_rota():
    response = _post(
        "/_teste/upload-campos", [("page", b"1", None), ("file", PDF, "a.pdf"), ("x", b"10.5", None)]
    )
    assert response.status_code == 200
    assert response.json()["fields"] == {"page": "1", "x": "10.5"}


def test_pdf_de_exatamente_20_mb_passa():
    pdf = PDF + b"0" * (20 * MB - len(PDF))
    response = _post("/_teste/upload", [("file", pdf, "a.pdf")])
    assert response.status_code == 200
    assert response.json()["size"] == 20 * MB


# --------------------------------------------------------------- tamanho (REQ-61)


def test_arquivo_de_21_mb_e_recusado_com_413():
    pdf = PDF + b"0" * (21 * MB - len(PDF))
    response = _post("/_teste/upload", [("file", pdf, "a.pdf")])
    assert response.status_code == 413
    assert response.json()["code"] == "DOC_002"


def test_um_byte_acima_do_limite_e_recusado():
    pdf = PDF + b"0" * (20 * MB + 1 - len(PDF))
    response = _post("/_teste/upload", [("file", pdf, "a.pdf")])
    assert response.status_code == 413


def test_content_length_acima_do_limite_e_recusado_sem_ler_o_corpo():
    lidos = []

    def corpo():
        lidos.append(1)
        yield b"x"

    response = client.post(
        "/_teste/upload",
        content=corpo(),
        headers={
            "Content-Type": "multipart/form-data; boundary=b",
            "Content-Length": str(20 * MB + MULTIPART_OVERHEAD_BYTES + 1),
        },
    )
    assert response.status_code == 413
    assert response.json()["code"] == "DOC_002"


def _asgi_post(body_chunks, headers: list[tuple[bytes, bytes]]):
    """Chama a app direto pelo ASGI, contando quantos pedaços do corpo ela pediu.

    O TestClient lê o corpo inteiro antes de entregá-lo à app, então não serve
    para provar que o servidor para de ler no meio.
    """
    import asyncio

    chunks = list(body_chunks)
    lidos = 0
    enviados: list[dict] = []

    async def receive():
        nonlocal lidos
        if lidos < len(chunks):
            lidos += 1
            return {"type": "http.request", "body": chunks[lidos - 1], "more_body": lidos < len(chunks)}
        return {"type": "http.disconnect"}

    async def send(message):
        enviados.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/_teste/upload",
        "raw_path": b"/_teste/upload",
        "query_string": b"",
        "headers": headers,
        "client": ("127.0.0.1", 5000),
        "server": ("testserver", 80),
    }
    asyncio.run(test_app(scope, receive, send))
    status = next(m["status"] for m in enviados if m["type"] == "http.response.start")
    return status, lidos, len(chunks)


def test_sem_content_length_a_leitura_para_no_limite():
    # Corpo em pedaços (Transfer-Encoding: chunked), sem Content-Length: o servidor
    # não pode ler os 40 MB inteiros antes de recusar.
    body, content_type = _multipart([("file", PDF + b"0" * (40 * MB), "a.pdf")])
    pedacos = [body[i : i + MB] for i in range(0, len(body), MB)]
    status, lidos, total = _asgi_post(pedacos, [(b"content-type", content_type.encode())])
    assert status == 413
    assert total > 40
    assert lidos <= 21, f"leu {lidos} MB de {total} antes de recusar"


def test_content_length_falso_nao_engana_o_limite():
    # O cliente declara 1 KB mas manda 40 MB: a contagem real dos bytes recusa.
    body, content_type = _multipart([("file", PDF + b"0" * (40 * MB), "a.pdf")])
    pedacos = [body[i : i + MB] for i in range(0, len(body), MB)]
    status, lidos, _ = _asgi_post(
        pedacos, [(b"content-type", content_type.encode()), (b"content-length", b"1024")]
    )
    assert status == 413
    assert lidos <= 21


def test_limite_vem_da_configuracao(monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "max_upload_mb", 1)
    response = _post("/_teste/upload", [("file", PDF + b"0" * MB, "a.pdf")])
    assert response.status_code == 413


# --------------------------------------------------------------- formato e campos


@pytest.mark.parametrize(
    "content_type",
    ["application/pdf", "application/json", "multipart/form-data", "text/plain; boundary=x", ""],
)
def test_content_type_que_nao_e_multipart_com_boundary_e_recusado(content_type):
    response = client.post("/_teste/upload", content=PDF, headers={"Content-Type": content_type})
    assert response.status_code == 400
    assert response.json()["code"] == "VAL_001"
    assert response.json()["fields"][0]["field"] == "file"


def test_sem_arquivo_e_recusado():
    response = _post("/_teste/upload-campos", [("page", b"1", None), ("x", b"1", None)])
    assert response.status_code == 400
    assert response.json()["fields"] == [{"field": "file", "reason": "campo obrigatório"}]


def test_campo_de_texto_faltando_e_recusado():
    response = _post("/_teste/upload-campos", [("file", PDF, "a.pdf"), ("page", b"1", None)])
    assert response.status_code == 400
    assert response.json()["fields"] == [{"field": "x", "reason": "campo obrigatório"}]


def test_dois_arquivos_sao_recusados():
    response = _post("/_teste/upload", [("file", PDF, "a.pdf"), ("file", PDF, "b.pdf")])
    assert response.status_code == 400
    assert response.json()["fields"][0]["reason"] == "envie um único arquivo"


def test_campo_nao_declarado_e_recusado():
    response = _post("/_teste/upload", [("file", PDF, "a.pdf"), ("user_id", b"1", None)])
    assert response.status_code == 400
    assert response.json()["fields"] == [{"field": "user_id", "reason": "campo não permitido"}]


def test_campo_repetido_e_recusado():
    response = _post(
        "/_teste/upload-campos",
        [("file", PDF, "a.pdf"), ("page", b"1", None), ("page", b"2", None), ("x", b"1", None)],
    )
    assert response.status_code == 400
    assert response.json()["fields"] == [{"field": "page", "reason": "campo repetido"}]


def test_campo_de_texto_longo_e_recusado():
    response = _post(
        "/_teste/upload-campos", [("file", PDF, "a.pdf"), ("page", b"1" * 257, None), ("x", b"1", None)]
    )
    assert response.status_code == 400
    assert response.json()["fields"][0]["field"] == "page"


def test_corpo_multipart_truncado_e_recusado():
    body, content_type = _multipart([("file", PDF, "a.pdf")])
    response = client.post("/_teste/upload", content=body[:-20], headers={"Content-Type": content_type})
    assert response.status_code == 400
    assert response.json()["code"] == "VAL_001"


def test_erro_de_upload_nao_ecoa_o_conteudo_do_arquivo():
    pdf = PDF + b"SEGREDO-DO-DOCUMENTO" + b"0" * (21 * MB)
    response = _post("/_teste/upload", [("file", pdf, "a.pdf")])
    assert response.status_code == 413
    assert "SEGREDO" not in response.text


def test_nada_e_gravado_em_arquivo_temporario(monkeypatch):
    # Seção 9.2: o PDF não vai para disco. Qualquer tentativa de criar arquivo temporário falha o teste.
    import tempfile

    def proibido(*args, **kwargs):
        raise AssertionError("upload tentou gravar em arquivo temporário")

    monkeypatch.setattr(tempfile, "SpooledTemporaryFile", proibido)
    monkeypatch.setattr(tempfile, "TemporaryFile", proibido)
    monkeypatch.setattr(tempfile, "NamedTemporaryFile", proibido)
    pdf = PDF + b"0" * (5 * MB)
    response = _post("/_teste/upload", [("file", pdf, "a.pdf")])
    assert response.status_code == 200
    assert response.json()["size"] == len(pdf)


# --------------------------------------------------------------- magic number (REQ-60)

EXE = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 120  # cabeçalho de um executável do Windows


@pytest.mark.parametrize(
    "conteudo",
    [
        EXE,  # executável renomeado para .pdf
        b"<html><script>alert(1)</script></html>",
        b"%PDF",  # só 4 bytes: falta o hífen
        b"%pdf-1.7\n",  # minúsculas
        b" %PDF-1.7\n",  # espaço antes
        b"\xef\xbb\xbf%PDF-1.7\n",  # BOM antes
        b"PK\x03\x04" + b"0" * 100,  # zip/docx
        b"",
    ],
)
def test_arquivo_que_nao_comeca_com_pdf_e_recusado(conteudo):
    response = _post("/_teste/upload", [("file", conteudo, "documento.pdf")])
    assert response.status_code == 400
    assert response.json()["code"] == "DOC_001"


def test_nome_e_content_type_da_parte_nao_contam():
    # O cliente controla o nome e o Content-Type; só os bytes decidem.
    response = _post("/_teste/upload", [("file", PDF, "foto.png")])
    assert response.status_code == 200


def test_magic_number_dividido_entre_pedacos_e_aceito():
    # Os 5 bytes podem chegar em pedaços diferentes da rede.
    body, content_type = _multipart([("file", PDF, "a.pdf")])
    inicio = body.index(b"%PDF-")
    pedacos = [body[: inicio + 2], body[inicio + 2 : inicio + 4], body[inicio + 4 :]]
    status, _, _ = _asgi_post(pedacos, [(b"content-type", content_type.encode())])
    assert status == 200


def test_arquivo_que_nao_e_pdf_para_a_leitura_logo_no_inicio():
    # Um executável de 15 MB é recusado depois de ler só o primeiro pedaço.
    body, content_type = _multipart([("file", EXE + b"\x00" * (15 * MB), "a.pdf")])
    pedacos = [body[i : i + MB] for i in range(0, len(body), MB)]
    status, lidos, total = _asgi_post(pedacos, [(b"content-type", content_type.encode())])
    assert status == 400
    assert total > 15
    assert lidos == 1, f"leu {lidos} MB antes de recusar"


def test_tamanho_declarado_e_conferido_antes_do_magic_number():
    # Com Content-Length acima do limite nada é lido, nem os 5 primeiros bytes.
    response = _post("/_teste/upload", [("file", EXE + b"\x00" * (21 * MB), "a.pdf")])
    assert response.status_code == 413
    assert response.json()["code"] == "DOC_002"


# --------------------------------------------------------------- QA caixa-branca (bloco PDF)


def test_boundary_longo_e_400_e_nao_500():
    body, content_type = _multipart([("file", PDF, "a.pdf")], boundary="a" * 300)
    response = client.post("/_teste/upload", content=body, headers={"Content-Type": content_type})
    assert response.status_code == 400
    assert response.json()["code"] == "VAL_001"


def test_content_length_com_digito_unicode_nao_vira_500():
    from fastapi import Request

    from app.core.errors import AppError
    from app.pdf.upload import read_pdf_upload

    scope = {
        "type": "http",
        "method": "POST",
        # "²" em latin-1: isdigit() diz que é dígito, mas int() falha.
        "headers": [(b"content-type", b"multipart/form-data; boundary=b"), (b"content-length", b"\xb2")],
    }

    async def receive():
        return {"type": "http.request", "body": b"--b--\r\n", "more_body": False}

    import asyncio

    with pytest.raises(AppError) as erro:
        asyncio.run(read_pdf_upload(Request(scope, receive), max_file_bytes=MB))
    assert erro.value.code.value == "VAL_001"  # chega ao fim sem arquivo: 400, não 500


def test_cliente_que_desconecta_no_meio_e_400():
    body, content_type = _multipart([("file", PDF + b"0" * (3 * MB), "a.pdf")])
    pedacos = [body[i : i + MB] for i in range(0, len(body), MB)][:2]  # manda 2 MB e some

    import asyncio

    enviados: list[dict] = []
    lidos = 0

    async def receive():
        nonlocal lidos
        if lidos < len(pedacos):
            lidos += 1
            return {"type": "http.request", "body": pedacos[lidos - 1], "more_body": True}
        return {"type": "http.disconnect"}

    async def send(message):
        enviados.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/_teste/upload",
        "raw_path": b"/_teste/upload",
        "query_string": b"",
        "headers": [(b"content-type", content_type.encode())],
        "client": ("127.0.0.1", 5000),
        "server": ("testserver", 80),
    }
    asyncio.run(test_app(scope, receive, send))
    assert next(m["status"] for m in enviados if m["type"] == "http.response.start") == 400


def test_epilogo_enorme_depois_do_arquivo_e_recusado_pela_contagem_total():
    # O python-multipart descarta o epílogo em silêncio: só a contagem total de bytes o barra.
    body, content_type = _multipart([("file", PDF, "a.pdf")])
    body += b"x" * (30 * MB)
    pedacos = [body[i : i + MB] for i in range(0, len(body), MB)]
    status, lidos, _ = _asgi_post(pedacos, [(b"content-type", content_type.encode())])
    assert status == 413
    assert lidos <= 21


def test_campo_de_texto_com_exatamente_256_bytes_passa():
    response = _post(
        "/_teste/upload-campos", [("file", PDF, "a.pdf"), ("page", b"1" * 256, None), ("x", b"1", None)]
    )
    assert response.status_code == 200


def test_disposition_diferente_de_form_data_e_recusada():
    body = (
        b'--qa\r\nContent-Disposition: attachment; name="file"; filename="a.pdf"\r\n\r\n'
        + PDF
        + b"\r\n--qa--\r\n"
    )
    response = client.post(
        "/_teste/upload", content=body, headers={"Content-Type": "multipart/form-data; boundary=qa"}
    )
    assert response.status_code == 400


def test_parte_sem_content_disposition_depois_de_uma_valida_e_recusada():
    body = (
        b'--qa\r\nContent-Disposition: form-data; name="file"; filename="a.pdf"\r\n\r\n'
        + PDF
        + b"\r\n--qa\r\nContent-Type: text/plain\r\n\r\nsem nome\r\n--qa--\r\n"
    )
    response = client.post(
        "/_teste/upload", content=body, headers={"Content-Type": "multipart/form-data; boundary=qa"}
    )
    assert response.status_code == 400


def test_magic_em_pedacos_de_um_byte_para_logo_depois_do_quinto():
    body, content_type = _multipart([("file", EXE + b"\x00" * MB, "a.pdf")])
    inicio = body.index(b"MZ")
    pedacos = [body[:inicio]] + [body[i : i + 1] for i in range(inicio, inicio + 10)] + [body[inicio + 10 :]]
    status, lidos, total = _asgi_post(pedacos, [(b"content-type", content_type.encode())])
    assert status == 400
    assert lidos == 6, f"leu {lidos} de {total} pedaços"


# --------------------------------------------------------------- QA caixa-preta: conexão, prazos e log


@pytest.mark.parametrize(
    ("partes", "status"),
    [
        ([("file", PDF + b"0" * (21 * MB), "a.pdf")], 413),
        ([("file", EXE, "a.pdf")], 400),
        ([("file", PDF, "a.pdf"), ("extra", b"1", None)], 400),
    ],
    ids=["grande", "nao-pdf", "campo-a-mais"],
)
def test_erro_de_upload_fecha_a_conexao(partes, status):
    # Sem Connection: close o uvicorn continua lendo e descartando o corpo (o QA mandou ~10 GB).
    response = _post("/_teste/upload", partes)
    assert response.status_code == status
    assert response.headers["connection"] == "close"


def _asgi_com_receive(receive):
    import asyncio

    enviados: list[dict] = []

    async def send(message):
        enviados.append(message)

    body, content_type = _multipart([("file", PDF, "a.pdf")])
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/_teste/upload",
        "raw_path": b"/_teste/upload",
        "query_string": b"",
        "headers": [(b"content-type", content_type.encode())],
        "client": ("127.0.0.1", 5000),
        "server": ("testserver", 80),
    }
    asyncio.run(asyncio.wait_for(test_app(scope, receive(body), send), 10))
    return next(m for m in enviados if m["type"] == "http.response.start")


def test_envio_parado_e_encerrado_pelo_prazo_sem_dados(monkeypatch):
    import asyncio

    monkeypatch.setattr("app.pdf.upload.UPLOAD_IDLE_TIMEOUT_SECONDS", 0.2)

    def receive(body):
        enviado = False

        async def _receive():
            nonlocal enviado
            if not enviado:
                enviado = True
                return {"type": "http.request", "body": body[:100], "more_body": True}
            await asyncio.Event().wait()  # cliente parado para sempre

        return _receive

    response = _asgi_com_receive(receive)
    assert response["status"] == 400
    assert (b"connection", b"close") in response["headers"]


def test_envio_a_conta_gotas_e_encerrado_pelo_prazo_total(monkeypatch):
    import asyncio

    monkeypatch.setattr("app.pdf.upload.UPLOAD_TOTAL_TIMEOUT_SECONDS", 0.5)

    def receive(body):
        posicao = 0

        async def _receive():
            nonlocal posicao
            await asyncio.sleep(0.05)  # 1 byte a cada 50 ms: nunca fica parado, nunca termina
            posicao += 1
            return {"type": "http.request", "body": body[posicao - 1 : posicao], "more_body": True}

        return _receive

    assert _asgi_com_receive(receive)["status"] == 400


def test_avisos_do_python_multipart_nao_vao_para_o_log():
    import logging

    assert logging.getLogger("python_multipart").getEffectiveLevel() >= logging.ERROR


@pytest.mark.parametrize("nome", ['fi"le', "file\x00", "<script>", "a" * 40])
def test_nome_de_campo_esquisito_nao_volta_na_resposta(nome):
    body = (
        b'--qa\r\nContent-Disposition: form-data; name="file"; filename="a.pdf"\r\n\r\n'
        + PDF
        + b'\r\n--qa\r\nContent-Disposition: form-data; name="'
        + nome.replace('"', '\\"').encode()
        + b'"\r\n\r\nx\r\n--qa--\r\n'
    )
    response = client.post(
        "/_teste/upload", content=body, headers={"Content-Type": "multipart/form-data; boundary=qa"}
    )
    assert response.status_code == 400
    assert nome not in response.text
    assert response.json()["fields"][0]["field"] == "campo"
