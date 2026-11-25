"""PDF com JavaScript é recusado (REQ-63).

Os PDFs são montados byte a byte, para cobrir as formas de esconder
JavaScript que uma busca de texto não pega (escape no nome, object stream,
xref quebrada, objeto órfão, atualização incremental) e as que não podem
ser falso positivo (a palavra "JavaScript" no texto da página).
"""

import io

import pikepdf
import pytest

from app.core.errors import AppError, ErrorCode
from app.pdf import client as pdf_client
from pdf_worker import protocol, task
from tests.conftest import make_signer

PAGE = b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>"
PAGES = b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>"
CATALOG = b"<< /Type /Catalog /Pages 2 0 R >>"


def raw_pdf(objects: dict[int, bytes], *, xref: bool = True) -> bytes:
    """PDF mínimo com os objetos dados (1 = catálogo). Calcula a tabela xref de verdade."""
    objects = {1: CATALOG, 2: PAGES, 3: PAGE, **objects}
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}
    for number in sorted(objects):
        offsets[number] = len(out)
        out += f"{number} 0 obj\n".encode() + objects[number] + b"\nendobj\n"
    size = max(objects) + 1
    start = len(out)
    if xref:
        out += f"xref\n0 {size}\n0000000000 65535 f \n".encode()
        for number in range(1, size):
            line = f"{offsets[number]:010d} 00000 n \n" if number in offsets else "0000000000 65535 f \n"
            out += line.encode()
    out += f"trailer\n<< /Size {size} /Root 1 0 R >>\nstartxref\n{start}\n%%EOF\n".encode()
    return bytes(out)


def stream(data: bytes) -> bytes:
    return f"<< /Length {len(data)} >>\nstream\n".encode() + data + b"\nendstream"


def worker_result(pdf: bytes) -> dict:
    header, _ = protocol.decode(
        protocol.reader_from_bytes(task.handle(protocol.encode({"op": "inspect", "args": {}}, pdf)))
    )
    return header


def _object_stream() -> bytes:
    # JavaScript dentro de um object stream comprimido: o texto "/JavaScript" some dos bytes.
    document = pikepdf.new()
    document.add_blank_page()
    acao = document.make_indirect(
        pikepdf.Dictionary(S=pikepdf.Name.JavaScript, JS=pikepdf.String("app.alert(1)"))
    )
    document.Root.OpenAction = acao
    buffer = io.BytesIO()
    document.save(buffer, object_stream_mode=pikepdf.ObjectStreamMode.generate, compress_streams=True)
    data = buffer.getvalue()
    assert b"/JavaScript" not in data and b"/JS" not in data, "o teste precisa do JS escondido"
    return data


def _incremental_update() -> bytes:
    # PDF limpo + atualização incremental que troca o catálogo por um com /OpenAction.
    original = raw_pdf({})
    novo_catalogo = b"<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>"
    prev = int(original.rsplit(b"startxref\n", 1)[1].split(b"\n")[0])
    out = bytearray(original)
    offset = len(out)
    out += b"1 0 obj\n" + novo_catalogo + b"\nendobj\n"
    start = len(out)
    out += f"xref\n1 1\n{offset:010d} 00000 n \ntrailer\n<< /Size 4 /Root 1 0 R /Prev {prev} >>\n".encode()
    out += f"startxref\n{start}\n%%EOF\n".encode()
    return bytes(out)


def _quebrar_xref(pdf: bytes) -> bytes:
    # Embaralha os offsets: o qpdf reconstrói a tabela e precisa achar o JS mesmo assim.
    head, tail = pdf.split(b"xref\n", 1)
    return head + b"xref\n" + tail.replace(b" 00000 n", b" 00000 n").replace(b"00000000", b"00000099", 3)


COM_JAVASCRIPT = {
    "open-action": {
        1: b"<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>"
    },
    "arvore-de-nomes": {
        1: b"<< /Type /Catalog /Pages 2 0 R /Names << /JavaScript 4 0 R >> >>",
        4: b"<< /Names [(a) 5 0 R] >>",
        5: b"<< /S /JavaScript /JS (app.alert(1)) >>",
    },
    "js-em-stream": {
        3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] "
        b"/AA << /O << /S /JavaScript /JS 4 0 R >> >> >>",
        4: stream(b"app.alert(1)"),
    },
    "anotacao-link": {
        3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Annots [4 0 R] >>",
        4: b"<< /Type /Annot /Subtype /Link /Rect [0 0 1 1] /A << /S /JavaScript /JS (x) >> >>",
    },
    "nome-js-com-escape": {1: b"<< /Type /Catalog /Pages 2 0 R /OpenAction << /J#53 (app.alert(1)) >> >>"},
    "acao-com-escape": {1: b"<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /Java#53cript >> >>"},
    "objeto-orfao": {4: b"<< /JS (app.alert(1)) >>"},
    "aninhado-fundo": {
        1: b"<< /Type /Catalog /Pages 2 0 R /X " + b"[" * 200 + b"<< /JS (x) >>" + b"]" * 200 + b" >>"
    },
    "uri-javascript": {
        3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Annots [4 0 R] >>",
        4: b"<< /Type /Annot /Subtype /Link /Rect [0 0 1 1] "
        b"/A << /S /URI /URI ( JaVa\tScRiPt:alert(1)) >> >>",
    },
    "formulario-xfa": {
        1: b"<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [] /XFA 4 0 R >> >>",
        4: stream(b"<xdp:xdp><script>app.alert(1)</script></xdp:xdp>"),
    },
    "objeto-orfao-com-aa": {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        4: b"<< /Title (x) /AA << /S /JavaScript /JS (x) >> >>",
    },
}


@pytest.mark.parametrize("nome", COM_JAVASCRIPT)
def test_pdf_com_javascript_e_recusado(nome):
    assert worker_result(raw_pdf(COM_JAVASCRIPT[nome])) == {"ok": False, "error": "HAS_JAVASCRIPT"}


@pytest.mark.parametrize(
    "pdf",
    [_object_stream(), _incremental_update(), _quebrar_xref(raw_pdf(COM_JAVASCRIPT["open-action"]))],
    ids=["object-stream-comprimido", "atualizacao-incremental", "xref-quebrada"],
)
def test_javascript_escondido_da_busca_de_texto_e_recusado(pdf):
    assert worker_result(pdf) == {"ok": False, "error": "HAS_JAVASCRIPT"}


SEM_JAVASCRIPT = {
    "pdf-limpo": {},
    "palavra-no-texto-da-pagina": {
        3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>",
        4: stream(b"BT /F1 12 Tf (JavaScript /JS /JavaScript) Tj ET"),
    },
    "palavra-numa-string": {1: b"<< /Type /Catalog /Pages 2 0 R /Lang (/JavaScript /JS) >>"},
    "link-https": {
        3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Annots [4 0 R] >>",
        4: b"<< /Type /Annot /Subtype /Link /Rect [0 0 1 1] "
        b"/A << /S /URI /URI (https://exemplo.com/javascript:) >> >>",
    },
    "nome-parecido": {1: b"<< /Type /Catalog /Pages 2 0 R /JSX 1 /JavaScriptX 2 /S /JavaScripts >>"},
}


@pytest.mark.parametrize("nome", SEM_JAVASCRIPT)
def test_pdf_sem_javascript_passa(nome):
    resultado = worker_result(raw_pdf(SEM_JAVASCRIPT[nome]))
    assert resultado["ok"] is True, resultado


def test_javascript_e_conferido_antes_das_paginas():
    # Um PDF sem páginas mas com JS diz HAS_JAVASCRIPT, não só UNPROCESSABLE.
    pdf = raw_pdf(
        {
            1: b"<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (x) >> >>",
            2: b"<< /Type /Pages /Kids [] /Count 0 >>",
        }
    )
    assert worker_result(pdf) == {"ok": False, "error": "HAS_JAVASCRIPT"}


# --------------------------------------------------------------- na API: assinatura e verificação


def test_api_recusa_javascript_na_assinatura_e_na_verificacao(fake_pdf_worker):
    pdf = raw_pdf(COM_JAVASCRIPT["open-action"])
    for chamada in (
        lambda: pdf_client.inspect(pdf),
        lambda: pdf_client.prepare_sign(
            pdf, page=1, x=0, y=0, seal_lines=["x"], signer_cert_pem=make_signer()[1]
        ),
        lambda: pdf_client.verify(pdf),
    ):
        with pytest.raises(AppError) as erro:
            chamada()
        assert erro.value.code == ErrorCode.DOC_HAS_JAVASCRIPT
        assert erro.value.spec.status == 400


# --------------------------------------------------------------- QA caixa-branca (bloco PDF)


def test_javascript_em_dicionario_direto_no_trailer():
    pdf = raw_pdf({}).replace(b"/Root 1 0 R >>", b"/Root 1 0 R /X << /JS (app.alert(1)) >> >>")
    assert b"/X << /JS" in pdf
    assert worker_result(pdf) == {"ok": False, "error": "HAS_JAVASCRIPT"}


def test_javascript_no_dicionario_de_um_stream():
    # A ação está no dicionário do próprio stream, não no conteúdo.
    pdf = raw_pdf(
        {
            1: b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>",
            4: b"<< /Length 1 /S /JavaScript /JS (x) >>\nstream\nx\nendstream",
        }
    )
    assert worker_result(pdf) == {"ok": False, "error": "HAS_JAVASCRIPT"}


# --------------------------------------------------------------- QA caixa-preta: falha fechada


def _sem_objeto_4_na_xref(pdf: bytes) -> bytes:
    # O objeto 4 continua no arquivo, mas a xref o marca como livre.
    linhas = pdf.split(b"\n")
    xref = linhas.index(b"xref")
    linhas[xref + 6] = b"0000000000 65535 f "
    return b"\n".join(linhas)


OBJETO_PERDIDO = {
    # O qpdf corta aninhamento acima de 500 níveis: o objeto com JS vira null.
    "aninhamento-acima-do-limite": {
        1: b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>",
        4: b"[" * 501 + b"<< /S /JavaScript /JS (x) >>" + b"]" * 501,
    },
    "cadeia-next-acima-do-limite": {
        1: b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>",
        4: b"<< /S /GoTo /D [3 0 R /Fit] /Next " * 600 + b"<< /S /JavaScript /JS (x) >>" + b" >>" * 600,
    },
    "dicionario-sem-fechar": {
        1: b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>",
        4: b"<< /S /JavaScript /JS (app.alert(1)) /Next << /S",
    },
    "string-sem-fechar": {
        1: b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>",
        4: b"<< /S /JavaScript /JS (app.alert(1) >>",
    },
}


@pytest.mark.parametrize("nome", OBJETO_PERDIDO)
def test_objeto_que_o_parser_perde_e_recusado_em_vez_de_passar_limpo(nome):
    # Falha fechada: se o qpdf descartou um objeto, não dá para garantir que não havia JS.
    resultado = worker_result(raw_pdf(OBJETO_PERDIDO[nome]))
    assert resultado["ok"] is False, resultado
    assert resultado["error"] in ("UNPROCESSABLE", "HAS_JAVASCRIPT")


def test_objeto_fora_da_xref_mas_no_arquivo_e_encontrado():
    pdf = _sem_objeto_4_na_xref(
        raw_pdf(
            {
                1: b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>",
                4: b"<< /S /JavaScript /JS (app.alert(1)) >>",
            }
        )
    )
    assert b"0000000000 65535 f \n" in pdf.split(b"trailer")[0].rsplit(b"xref", 1)[1]
    assert worker_result(pdf) == {"ok": False, "error": "HAS_JAVASCRIPT"}


def _link(uri: bytes) -> dict:
    return {
        3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Annots [4 0 R] >>",
        4: b"<< /Type /Annot /Subtype /Link /Rect [0 0 1 1] /A << /S /URI /URI " + uri + b" >> >>",
    }


@pytest.mark.parametrize(
    "uri",
    [
        b"<FEFF006A006100760061007300630072006900700074003A0078>",  # UTF-16BE com BOM
        b"<EFBBBF6A6176617363726970743A78>",  # BOM UTF-8
        b"(\\000javascript:x)",  # nulo antes
    ],
    ids=["utf16-bom", "utf8-bom", "nulo-antes"],
)
def test_uri_javascript_codificada_e_recusada(uri):
    assert worker_result(raw_pdf(_link(uri))) == {"ok": False, "error": "HAS_JAVASCRIPT"}


def test_base_javascript_no_catalogo_e_recusada():
    pdf = raw_pdf({1: b"<< /Type /Catalog /Pages 2 0 R /URI << /Base (javascript:alert) >> >>"})
    assert worker_result(pdf) == {"ok": False, "error": "HAS_JAVASCRIPT"}


def test_pdf_grande_e_limpo_continua_aceito():
    # A segunda passada (xref reconstruída) não pode recusar nem pesar no PDF normal.
    from tests.conftest import make_pdf

    pdf = make_pdf(pages=400)
    assert worker_result(pdf)["result"]["page_count"] == 400


def _com_avisos(monkeypatch, *avisos: str) -> None:
    import pikepdf

    original = pikepdf.Pdf.get_warnings
    monkeypatch.setattr(pikepdf.Pdf, "get_warnings", lambda self: [*original(self), *avisos])


def test_aviso_de_objeto_perdido_do_qpdf_recusa_o_pdf(monkeypatch):
    # Com o limite de memória da tarefa, um object stream gigante só gera um aviso
    # (bad_alloc) e o objeto vira null. O aviso tem que recusar, nunca passar limpo.
    _com_avisos(monkeypatch, "(offset 291): error decoding stream data for object 10 0: std::bad_alloc")
    assert worker_result(raw_pdf({})) == {"ok": False, "error": "UNPROCESSABLE"}


def test_aviso_de_reparo_comum_nao_recusa(monkeypatch):
    _com_avisos(monkeypatch, "file is damaged", "Attempting to reconstruct cross-reference table")
    assert worker_result(raw_pdf({}))["ok"] is True
