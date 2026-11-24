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


# --------------------------------------------------------------- QA caixa-branca (bloco PDF)

import struct  # noqa: E402
import time  # noqa: E402


def _rodar(server, raw: bytes) -> dict:
    return protocol.decode(protocol.reader_from_bytes(asyncio.run(server._run_task(raw))))[0]


def _filho(monkeypatch, codigo: str) -> None:
    """Troca o processo da tarefa por um Python com `codigo`, mantendo os limites e o env."""
    original = asyncio.create_subprocess_exec

    async def substituto(*args, **kwargs):
        return await original(sys.executable, "-c", codigo, **kwargs)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", substituto)


PEDIDO = protocol.encode({"op": "inspect", "args": {}}, b"x")


def test_tarefa_travada_e_morta_com_todo_o_grupo(server, monkeypatch):
    # O neto (sleep) também morre: o kill é no grupo de processos da tarefa.
    monkeypatch.setattr(server, "TASK_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr(server, "_limit_task", lambda: None)  # precisa poder criar o neto
    _filho(
        monkeypatch,
        "import subprocess, sys, time; subprocess.Popen(['sleep', '60']); "
        "sys.stdin.buffer.read(); time.sleep(60)",
    )
    inicio = time.monotonic()
    assert _rodar(server, PEDIDO) == {"ok": False, "error": "TIMEOUT"}
    assert time.monotonic() - inicio < 5
    time.sleep(0.5)
    vivos = [
        p
        for p in os.listdir("/proc")
        if p.isdigit()
        and Path(f"/proc/{p}/cmdline").exists()
        and Path(f"/proc/{p}/cmdline").read_bytes() == b"sleep\x0060\x00"
    ]
    assert vivos == []


def test_filho_que_sai_com_erro_depois_de_responder_e_unprocessable(server, monkeypatch):
    resposta = protocol.encode({"ok": True, "result": {"page_count": 1, "pages": []}})
    _filho(
        monkeypatch,
        f"import sys; sys.stdin.buffer.read(); sys.stdout.buffer.write({resposta!r}); sys.exit(3)",
    )
    assert _rodar(server, PEDIDO) == {"ok": False, "error": "UNPROCESSABLE"}


def test_filho_que_escreve_lixo_e_unprocessable(server, monkeypatch):
    _filho(monkeypatch, "import sys; sys.stdin.buffer.read(); sys.stdout.buffer.write(b'ok, tudo certo')")
    assert _rodar(server, PEDIDO) == {"ok": False, "error": "UNPROCESSABLE"}


def test_filho_recebe_so_o_ambiente_minimo(server, monkeypatch):
    monkeypatch.setenv("SEGREDO_DO_SERVIDOR", "nao-pode-vazar")
    codigo = (
        "import os, sys; sys.stdin.buffer.read(); from pdf_worker import protocol; "
        "sys.stdout.buffer.write(protocol.encode({'ok': True, 'result': dict(os.environ)}))"
    )
    _filho(monkeypatch, codigo)
    monkeypatch.setattr(server, "TASK_ENV", {**server.TASK_ENV, "PYTHONPATH": str(BACKEND)})
    env = _rodar(server, PEDIDO)["result"]
    assert "SEGREDO_DO_SERVIDOR" not in env
    assert set(env) <= set(server.TASK_ENV) | {"LC_CTYPE"}


def _com_limites(server, codigo: str) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 - comando fixo do próprio teste
        [sys.executable, "-c", codigo],
        preexec_fn=server._limit_task,  # noqa: PLW1509
        capture_output=True,
        timeout=30,
    )


def test_tarefa_tem_limite_de_cpu(server, monkeypatch):
    monkeypatch.setattr(server, "TASK_TIMEOUT_SECONDS", 1)
    inicio = time.monotonic()
    result = _com_limites(server, "while True: pass")
    assert result.returncode in (-24, -9)  # SIGXCPU no limite, SIGKILL no teto
    assert time.monotonic() - inicio < 5


def test_tarefa_tem_limite_de_descritores(server):
    result = _com_limites(server, "fs = [open('/dev/null') for _ in range(64)]")
    assert result.returncode != 0
    assert b"Too many open files" in result.stderr


def test_tarefa_nao_cria_processos(server):
    # Um exploit no parser não consegue deixar um processo vivo depois do fim da tarefa.
    result = _com_limites(server, "import os; os.fork()")
    assert result.returncode != 0
    assert b"Resource temporarily unavailable" in result.stderr


def test_inspect_real_funciona_com_todos_os_limites(server):
    # Os limites não podem quebrar o caso normal (pikepdf com NPROC 0, AS 256 MB, NOFILE 32).
    raw = protocol.encode({"op": "inspect", "args": {}}, make_pdf(pages=50))
    assert _rodar(server, raw)["result"]["page_count"] == 50


def test_leitura_recusa_tamanhos_declarados_sem_ler_o_resto(server):
    async def ler(dados: bytes):
        reader = asyncio.StreamReader()
        reader.feed_data(dados)  # sem feed_eof: se tentar ler o corpo, trava e estoura o wait_for
        return await asyncio.wait_for(server._read_request(reader), 1)

    for dados in (
        protocol.MAGIC + struct.pack(">I", protocol.MAX_HEADER_BYTES + 1),
        protocol.MAGIC + struct.pack(">I", 2) + b"{}" + struct.pack(">Q", protocol.MAX_BODY_BYTES + 1),
        protocol.MAGIC + struct.pack(">I", 2) + b"[]" + struct.pack(">Q", 10),
    ):
        with pytest.raises(protocol.ProtocolError):
            asyncio.run(ler(dados))


def test_fila_cheia_responde_busy_no_prazo(server, tmp_path, monkeypatch):
    import concurrent.futures

    monkeypatch.setattr(server, "MAX_CONCURRENT_TASKS", 1)
    monkeypatch.setattr(server, "QUEUE_TIMEOUT_SECONDS", 0.5)
    original = server._run_task

    async def lenta(raw):
        await asyncio.sleep(3)
        return await original(raw)

    monkeypatch.setattr(server, "_run_task", lenta)
    raw = protocol.encode({"op": "inspect", "args": {}}, make_pdf())

    def cenario(caminho):
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            primeira = pool.submit(_call_socket, caminho, raw)
            time.sleep(0.3)
            inicio = time.monotonic()
            segunda = protocol.decode(protocol.reader_from_bytes(_call_socket(caminho, raw)))[0]
            espera = time.monotonic() - inicio
            return protocol.decode(protocol.reader_from_bytes(primeira.result()))[0], segunda, espera

    primeira, segunda, espera = _with_server(server, tmp_path, monkeypatch, cenario)
    assert primeira["ok"] is True
    assert segunda == {"ok": False, "error": "BUSY"}
    assert espera < 2


def test_orcamento_de_tempo_cabe_no_timeout_da_api(server):
    api_timeout = 30  # PDF_WORKER_TIMEOUT_SECONDS padrão
    assert (
        server.QUEUE_TIMEOUT_SECONDS + server.READ_TIMEOUT_SECONDS + server.TASK_TIMEOUT_SECONDS < api_timeout
    )


def test_ambiente_do_worker_sem_rede_e_sem_segredos():
    # Critério do REQ-62, no container de testes (mesmo isolamento do pdf-worker no compose).
    assert sorted(os.listdir("/sys/class/net")) == ["lo"]
    with pytest.raises(OSError):
        socket.create_connection(("1.1.1.1", 80), timeout=3)
    # O ambiente com que o container nasceu (o conftest põe variáveis de teste no os.environ).
    ambiente = Path("/proc/1/environ").read_bytes().split(b"\0")
    nomes = [linha.split(b"=", 1)[0].decode() for linha in ambiente if linha]
    marcas = ("SECRET", "PASSWORD", "TOKEN", "PEPPER", "MASTER", "DATABASE", "JWT")
    assert nomes, "não consegui ler o ambiente do container"
    assert [k for k in nomes if any(m in k.upper() for m in marcas)] == []
