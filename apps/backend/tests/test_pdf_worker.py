"""pdf-worker isolado (REQ-62): protocolo, operações, processo da tarefa e cliente da API.

O isolamento do container (sem rede, só leitura, sem segredos) é conferido no
Docker; aqui fica a lógica, que roda em qualquer plataforma.
"""

import io
import logging
import socket
import struct
import subprocess
import sys
import threading
from pathlib import Path

import pikepdf
import pytest

from app.core.errors import AppError, ErrorCode
from app.pdf import client as pdf_client
from pdf_worker import protocol, task
from tests.conftest import make_pdf

BACKEND = Path(__file__).resolve().parent.parent


def _request(op="inspect", args=None, pdf=b"") -> bytes:
    return protocol.encode({"op": op, "args": {} if args is None else args}, pdf)


def _response(raw: bytes) -> tuple[dict, bytes]:
    return protocol.decode(protocol.reader_from_bytes(raw))


# --------------------------------------------------------------- protocolo


def test_protocolo_ida_e_volta():
    header, body = _response(protocol.encode({"op": "x", "args": {"a": 1}}, b"%PDF-\x00\xff"))
    assert header == {"op": "x", "args": {"a": 1}}
    assert body == b"%PDF-\x00\xff"


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"XXXX" + b"\x00" * 20,  # formato desconhecido
        protocol.MAGIC + struct.pack(">I", protocol.MAX_HEADER_BYTES + 1),  # cabeçalho declarado grande
        protocol.MAGIC + struct.pack(">I", 2) + b"[]" + struct.pack(">Q", 0),  # cabeçalho não é objeto
        protocol.MAGIC + struct.pack(">I", 3) + b"{x}" + struct.pack(">Q", 0),  # JSON inválido
        protocol.MAGIC + struct.pack(">I", 2) + b"{}" + struct.pack(">Q", protocol.MAX_BODY_BYTES + 1),
        protocol.encode({"op": "x"}, b"abcdef")[:-2],  # truncado
    ],
)
def test_protocolo_recusa_mensagem_invalida(raw):
    with pytest.raises(protocol.ProtocolError):
        _response(raw)


def test_protocolo_respeita_limite_de_corpo_do_leitor():
    with pytest.raises(protocol.ProtocolError):
        protocol.decode(protocol.reader_from_bytes(protocol.encode({}, b"x" * 100)), max_body=99)


# --------------------------------------------------------------- operação inspect


def test_inspect_devolve_paginas_e_tamanhos():
    pdf = make_pdf(pages=3, size=(612, 792))
    header, body = _response(task.handle(_request(pdf=pdf)))
    assert header == {
        "ok": True,
        "result": {"page_count": 3, "pages": [{"width": 612.0, "height": 792.0}] * 3},
    }
    assert body == b""


def _protegido_por_senha() -> bytes:
    document = pikepdf.new()
    document.add_blank_page()
    buffer = io.BytesIO()
    document.save(buffer, encryption=pikepdf.Encryption(owner="dono", user="senha-do-leitor"))
    return buffer.getvalue()


@pytest.mark.parametrize(
    "pdf",
    [
        b"%PDF-1.7\nisto nao e um pdf",
        b"%PDF-",
        make_pdf()[:200],  # truncado
        _protegido_por_senha(),
    ],
    ids=["lixo", "so-magic", "truncado", "com-senha"],
)
def test_pdf_que_nao_da_para_abrir_e_unprocessable(pdf):
    header, _ = _response(task.handle(_request(pdf=pdf)))
    assert header == {"ok": False, "error": "UNPROCESSABLE"}


@pytest.mark.parametrize(
    "raw",
    [
        _request(op="apagar_tudo"),
        _request(op=None),
        protocol.encode({"op": "inspect", "args": ["nao", "e", "dict"]}),
        b"lixo",
    ],
    ids=["op-desconhecida", "op-nula", "args-invalidos", "lixo"],
)
def test_pedido_invalido_e_bad_request(raw):
    header, _ = _response(task.handle(raw))
    assert header == {"ok": False, "error": "BAD_REQUEST"}


def test_falha_inesperada_vira_internal_sem_detalhes(monkeypatch):
    def explode(pdf, args):
        raise RuntimeError("conteúdo secreto do documento")

    monkeypatch.setitem(task.run.__globals__["OPERATIONS"], "inspect", explode)
    raw = task.handle(_request(pdf=make_pdf()))
    assert _response(raw)[0] == {"ok": False, "error": "INTERNAL"}
    assert b"secreto" not in raw


def test_tarefa_roda_como_processo_separado():
    # O mesmo comando que o servidor usa no container, aqui sem os limites do Linux.
    pdf = make_pdf(pages=2)
    result = subprocess.run(
        [sys.executable, "-E", "-s", "-m", "pdf_worker.task"],
        input=_request(pdf=pdf),
        capture_output=True,
        cwd=BACKEND,
        timeout=60,
        check=True,
    )
    assert _response(result.stdout)[0]["result"]["page_count"] == 2
    assert result.stderr == b""


# --------------------------------------------------------------- cliente da API


def test_cliente_inspect_pelo_worker(fake_pdf_worker):
    info = pdf_client.inspect(make_pdf(pages=2, size=(300, 400)))
    assert info.page_count == 2
    assert info.pages[1] == pdf_client.PageSize(300.0, 400.0)
    pedido, pdf = _response(fake_pdf_worker[0])
    assert pedido == {"op": "inspect", "args": {}}
    assert pdf.startswith(b"%PDF-")


def test_sign_e_verify_passam_pelo_worker_antes_de_tudo(fake_pdf_worker):
    with pytest.raises(AppError) as erro:
        pdf_client.verify(b"%PDF-1.7\nquebrado")
    assert erro.value.code == ErrorCode.DOC_UNPROCESSABLE
    with pytest.raises(AppError) as erro:
        pdf_client.prepare_sign(b"%PDF-1.7\nquebrado", page=1, x=0, y=0, seal_lines=[], signer_cert_pem=b"")
    assert erro.value.code == ErrorCode.DOC_UNPROCESSABLE
    assert len(fake_pdf_worker) == 2


def _worker_respondendo(monkeypatch, resposta: bytes, recebido: list | None = None):
    def connect(path, timeout):
        api_side, worker_side = socket.socketpair()
        api_side.settimeout(timeout)

        def serve():
            with worker_side:
                while chunk := worker_side.recv(65536):
                    if recebido is not None:
                        recebido.append(chunk)
                worker_side.sendall(resposta)

        threading.Thread(target=serve, daemon=True).start()
        return api_side

    monkeypatch.setattr("app.pdf.client._connect", connect)


@pytest.mark.parametrize(
    ("erro_do_worker", "esperado"),
    [
        ("UNPROCESSABLE", ErrorCode.DOC_UNPROCESSABLE),
        ("TIMEOUT", ErrorCode.DOC_UNPROCESSABLE),
        ("HAS_JAVASCRIPT", ErrorCode.DOC_HAS_JAVASCRIPT),
        ("INVALID_POSITION", ErrorCode.DOC_INVALID_POSITION),
        ("INTERNAL", ErrorCode.INTERNAL),
        ("BAD_REQUEST", ErrorCode.INTERNAL),
        ("CODIGO_NOVO", ErrorCode.INTERNAL),
    ],
)
def test_cliente_traduz_os_erros_do_worker(monkeypatch, erro_do_worker, esperado):
    _worker_respondendo(monkeypatch, protocol.error(erro_do_worker))
    with pytest.raises(AppError) as erro:
        pdf_client.inspect(make_pdf())
    assert erro.value.code == esperado


@pytest.mark.parametrize(
    "resposta",
    [
        b"",  # worker fechou sem responder
        b"lixo",
        protocol.encode({"ok": True}),  # sem result
        protocol.encode({"ok": True, "result": {"page_count": "x", "pages": []}}),
        protocol.encode({"ok": True, "result": {"pages": [{"width": 1}]}}),
    ],
    ids=["vazia", "lixo", "sem-result", "page-count-invalido", "pagina-incompleta"],
)
def test_resposta_invalida_do_worker_vira_500(monkeypatch, resposta):
    _worker_respondendo(monkeypatch, resposta)
    with pytest.raises(AppError) as erro:
        pdf_client.inspect(make_pdf())
    assert erro.value.code == ErrorCode.INTERNAL


def test_worker_fora_do_ar_vira_500_sem_vazar_detalhes(monkeypatch, caplog):
    def recusa(path, timeout):
        raise ConnectionRefusedError(f"não conectou em {path}")

    monkeypatch.setattr("app.pdf.client._connect", recusa)
    monkeypatch.setattr(logging.getLogger("saferdocs.pdf"), "disabled", False)
    with caplog.at_level(logging.ERROR, logger="saferdocs.pdf"), pytest.raises(AppError) as erro:
        pdf_client.inspect(make_pdf())
    assert erro.value.code == ErrorCode.INTERNAL
    assert "ConnectionRefusedError" in caplog.text
    assert "/run/pdf" not in caplog.text


def test_worker_que_nao_responde_estoura_o_timeout(monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "pdf_worker_timeout_seconds", 1)

    def connect(path, timeout):
        api_side, worker_side = socket.socketpair()
        api_side.settimeout(timeout)
        connect.mantido = worker_side  # segura a outra ponta aberta e calada
        return api_side

    monkeypatch.setattr("app.pdf.client._connect", connect)
    with pytest.raises(AppError) as erro:
        pdf_client.inspect(make_pdf())
    assert erro.value.code == ErrorCode.INTERNAL
    connect.mantido.close()


def test_cliente_manda_o_pdf_inteiro_e_fecha_a_escrita(monkeypatch):
    recebido: list[bytes] = []
    _worker_respondendo(
        monkeypatch,
        protocol.encode({"ok": True, "result": {"page_count": 1, "pages": [{"width": 1, "height": 2}]}}),
        recebido,
    )
    pdf = make_pdf()
    pdf_client.inspect(pdf)
    header, body = _response(b"".join(recebido))
    assert header["op"] == "inspect"
    assert body == pdf


def test_socket_unix_ausente_no_windows_vira_500(monkeypatch):
    # Sem AF_UNIX (Windows), a API não consegue falar com o worker: erro interno claro, não crash.
    monkeypatch.delattr(socket, "AF_UNIX", raising=False)
    with pytest.raises(AppError) as erro:
        pdf_client.inspect(make_pdf())
    assert erro.value.code == ErrorCode.INTERNAL


def test_inspect_com_o_maximo_de_paginas_cabe_na_resposta():
    # Achado no QA do container: com 3000 páginas o cabeçalho passava de 64 KB e virava INTERNAL.
    from pdf_worker.ops import MAX_PAGES

    header, _ = _response(task.handle(_request(pdf=make_pdf(pages=MAX_PAGES))))
    assert header["ok"] is True
    assert header["result"]["page_count"] == MAX_PAGES


def test_pdf_acima_do_maximo_de_paginas_e_unprocessable():
    from pdf_worker.ops import MAX_PAGES

    header, _ = _response(task.handle(_request(pdf=make_pdf(pages=MAX_PAGES + 1))))
    assert header == {"ok": False, "error": "UNPROCESSABLE"}


# --------------------------------------------------------------- QA caixa-branca (bloco PDF)


def test_worker_ocupado_vira_429_com_retry_after(monkeypatch):
    _worker_respondendo(monkeypatch, protocol.error("BUSY"))
    with pytest.raises(AppError) as erro:
        pdf_client.inspect(make_pdf())
    assert erro.value.code == ErrorCode.RATE_LIMITED
    assert erro.value.headers == {"Retry-After": str(pdf_client.BUSY_RETRY_AFTER_SECONDS)}


def test_memoria_estourada_no_parser_e_unprocessable(monkeypatch):
    # README e client prometem DOC_004 para PDF que estoura memória, não 500.
    def explode(pdf, args):
        raise MemoryError

    monkeypatch.setitem(task.run.__globals__["OPERATIONS"], "inspect", explode)
    assert _response(task.handle(_request(pdf=make_pdf())))[0] == {"ok": False, "error": "UNPROCESSABLE"}


# --------------------------------------------------------------- critério do REQ-62 na configuração


def _compose() -> dict:
    import yaml

    return yaml.safe_load((BACKEND.parent.parent / "docker-compose.yml").read_text(encoding="utf-8"))


def test_compose_isola_o_pdf_worker():
    worker = _compose()["services"]["pdf-worker"]
    assert worker["network_mode"] == "none"  # sem rede
    assert worker["read_only"] is True
    assert worker["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in worker["security_opt"]
    assert worker["user"] == "10001:10001"
    assert worker["init"] is True
    assert worker["mem_limit"] and worker["pids_limit"] and worker["cpus"]
    # Sem segredos: não lê o .env nem recebe variáveis.
    assert "env_file" not in worker
    assert "environment" not in worker
    assert worker["volumes"] == ["pdfsock:/run/pdf"]


def test_compose_api_so_conecta_no_socket():
    backend = _compose()["services"]["backend"]
    assert "pdfsock:/run/pdf:ro" in backend["volumes"]
    assert backend["group_add"] == ["10001"]
