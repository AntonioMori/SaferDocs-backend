"""Servidor do pdf-worker (REQ-62): socket Unix, processo por tarefa e limites.

Só roda no Linux (socket Unix e limites do `resource`). No Windows os testes
são pulados; para rodar, use o container de testes descrito no README:

    docker compose --profile test run --rm worker-tests
"""

import asyncio
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform == "win32" or not hasattr(socket, "AF_UNIX"), reason="o servidor do worker só roda no Linux"
)

from pdf_worker import protocol  # noqa: E402
from tests.conftest import make_pdf  # noqa: E402

BACKEND = Path(__file__).resolve().parent.parent


@pytest.fixture
def server(monkeypatch):
    from pdf_worker import server as server_module

    monkeypatch.chdir(BACKEND)  # o processo da tarefa importa pdf_worker a partir daqui
    return server_module


def _call_socket(path: str, raw: bytes) -> bytes:
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(30)
        sock.connect(path)
        sock.sendall(raw)
        sock.shutdown(socket.SHUT_WR)
        chunks = []
        while chunk := sock.recv(65536):
            chunks.append(chunk)
    return b"".join(chunks)


def _with_server(server, tmp_path, monkeypatch, cenario):
    caminho = str(tmp_path / "worker.sock")
    monkeypatch.setattr(server, "SOCKET_PATH", caminho)

    async def run():
        task = asyncio.create_task(server.serve())
        for _ in range(100):
            if Path(caminho).exists():
                break
            await asyncio.sleep(0.05)
        try:
            return await asyncio.to_thread(cenario, caminho)
        finally:
            task.cancel()

    return asyncio.run(run())


def test_servidor_responde_pelo_socket_unix(server, tmp_path, monkeypatch):
    def cenario(caminho):
        return _call_socket(caminho, protocol.encode({"op": "inspect", "args": {}}, make_pdf(pages=2)))

    header, _ = protocol.decode(
        protocol.reader_from_bytes(_with_server(server, tmp_path, monkeypatch, cenario))
    )
    assert header["result"]["page_count"] == 2


def test_socket_so_para_dono_e_grupo(server, tmp_path, monkeypatch):
    def cenario(caminho):
        return oct(os.stat(caminho).st_mode & 0o777)

    assert _with_server(server, tmp_path, monkeypatch, cenario) == "0o660"


def test_pedido_malformado_no_socket_e_bad_request(server, tmp_path, monkeypatch):
    def cenario(caminho):
        return _call_socket(caminho, b"GET / HTTP/1.1\r\n\r\n")

    header, _ = protocol.decode(
        protocol.reader_from_bytes(_with_server(server, tmp_path, monkeypatch, cenario))
    )
    assert header == {"ok": False, "error": "BAD_REQUEST"}


def test_tarefa_que_estoura_o_tempo_e_morta(server, monkeypatch):
    monkeypatch.setattr(server, "TASK_TIMEOUT_SECONDS", 0.01)
    raw = protocol.encode({"op": "inspect", "args": {}}, make_pdf())
    header, _ = protocol.decode(protocol.reader_from_bytes(asyncio.run(server._run_task(raw))))
    assert header == {"ok": False, "error": "TIMEOUT"}


def test_tarefa_que_morre_vira_unprocessable(server, monkeypatch):
    # Simula o parser sendo derrubado por um PDF malicioso: o processo sai sem resposta.
    original = asyncio.create_subprocess_exec

    async def morre(*args, **kwargs):
        return await original(sys.executable, "-c", "import os; os._exit(139)", **kwargs)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", morre)
    raw = protocol.encode({"op": "inspect", "args": {}}, make_pdf())
    header, _ = protocol.decode(protocol.reader_from_bytes(asyncio.run(server._run_task(raw))))
    assert header == {"ok": False, "error": "UNPROCESSABLE"}


def test_processo_da_tarefa_nao_grava_arquivo(server, tmp_path):
    alvo = tmp_path / "vazou.pdf"
    # RLIMIT_FSIZE 0: o arquivo até pode ser criado vazio, mas nenhum byte do PDF é gravado.
    codigo = f"f = open({str(alvo)!r}, 'wb'); f.write(b'%PDF-conteudo'); f.flush()"
    result = subprocess.run(  # noqa: S603 - comando fixo do próprio teste
        [sys.executable, "-c", codigo],
        preexec_fn=server._limit_task,  # noqa: PLW1509
        capture_output=True,
        timeout=30,
    )
    assert result.returncode != 0
    assert b"File too large" in result.stderr
    assert not alvo.exists() or alvo.stat().st_size == 0


def test_processo_da_tarefa_tem_limite_de_memoria(server):
    result = subprocess.run(
        [sys.executable, "-c", "b = bytearray(2 * 1024**3)"],
        preexec_fn=server._limit_task,  # noqa: PLW1509
        capture_output=True,
        timeout=30,
    )
    assert result.returncode != 0
    assert b"MemoryError" in result.stderr


def test_falha_ao_criar_a_tarefa_responde_internal(server, monkeypatch):
    # Sem processo não há isolamento: o servidor responde INTERNAL em vez de fechar calado.
    async def falha(*args, **kwargs):
        raise OSError("fork falhou")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", falha)
    raw = protocol.encode({"op": "inspect", "args": {}}, make_pdf())
    header, _ = protocol.decode(protocol.reader_from_bytes(asyncio.run(server._run_task(raw))))
    assert header == {"ok": False, "error": "INTERNAL"}
