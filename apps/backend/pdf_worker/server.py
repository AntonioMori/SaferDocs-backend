"""Servidor do pdf-worker: `python -m pdf_worker.server` (só Linux).

Escuta um socket Unix no volume compartilhado com a API. Para cada pedido:

1. lê a mensagem inteira, com limite de tamanho e de tempo;
2. cria um processo novo (`pdf_worker.task`) com limites do sistema:
   tempo de CPU, memória, nenhum arquivo gravado e poucos descritores;
3. devolve a resposta dele. Se o processo estourar o tempo é morto
   (`TIMEOUT`); se morrer sozinho, a resposta é `UNPROCESSABLE`.

O isolamento de rede, de segredos e do sistema de arquivos vem do container
(ver `docker-compose.yml`): sem rede, raiz só leitura, sem capabilities e
sem nenhuma variável de ambiente com segredo.
"""

import asyncio
import contextlib
import json
import logging
import math
import os
import resource
import signal
import stat
import subprocess
import sys
from functools import partial

from pdf_worker.protocol import (
    ERR_BAD_REQUEST,
    ERR_BUSY,
    ERR_INTERNAL,
    ERR_TIMEOUT,
    ERR_UNPROCESSABLE,
    MAGIC,
    MAX_BODY_BYTES,
    MAX_HEADER_BYTES,
    ProtocolError,
    decode,
    error,
    reader_from_bytes,
)

logger = logging.getLogger("pdf_worker")

SOCKET_PATH = os.environ.get("PDF_WORKER_SOCKET", "/run/pdf/worker.sock")
# Orçamento de tempo de um pedido: fila + leitura + tarefa = 25 s, abaixo do
# PDF_WORKER_TIMEOUT_SECONDS da API (30). Assim a API recebe sempre uma resposta
# do worker (BUSY, TIMEOUT...) em vez de estourar o próprio timeout.
QUEUE_TIMEOUT_SECONDS = 5
READ_TIMEOUT_SECONDS = 5
TASK_TIMEOUT_SECONDS = 15
# Orçamento de memória (mem_limit 512m no compose): no máximo MAX_CONCURRENT_TASKS
# pedidos em memória no servidor (até 2 x o PDF cada) + as tarefas. Medido: um
# inspect de 20 MB chega a ~110 MB de memória virtual.
MAX_CONCURRENT_TASKS = 2
TASK_MEMORY_BYTES = 256 * 1024 * 1024
TASK_ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"}


def _limit_task() -> None:
    """Roda no processo filho, antes do Python da tarefa começar."""
    cpu_seconds = max(1, math.ceil(TASK_TIMEOUT_SECONDS))  # setrlimit só aceita inteiros
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 1))
    resource.setrlimit(resource.RLIMIT_AS, (TASK_MEMORY_BYTES, TASK_MEMORY_BYTES))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))  # não grava arquivo nenhum
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))  # sem core dump com o conteúdo do PDF
    # Não cria processos nem threads: um exploit no parser não sobrevive ao fim da tarefa
    # (fork + setsid escaparia do killpg) nem deixa um processo escutando no socket.
    resource.setrlimit(resource.RLIMIT_NPROC, (0, 0))


async def _read_request(reader: asyncio.StreamReader) -> bytes:
    """Lê uma mensagem inteira conferindo os tamanhos declarados antes de alocar."""
    raw = bytearray(await reader.readexactly(len(MAGIC) + 4))
    if raw[: len(MAGIC)] != MAGIC:
        raise ProtocolError("formato desconhecido")
    header_len = int.from_bytes(raw[len(MAGIC) :], "big")
    if header_len > MAX_HEADER_BYTES:
        raise ProtocolError("cabeçalho grande demais")
    raw += await reader.readexactly(header_len + 8)
    body_len = int.from_bytes(raw[-8:], "big")
    if body_len > MAX_BODY_BYTES:
        raise ProtocolError("corpo grande demais")
    # Confere o cabeçalho antes de gastar um processo, sem copiar o corpo.
    try:
        header = json.loads(raw[len(MAGIC) + 4 : len(MAGIC) + 4 + header_len])
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProtocolError("cabeçalho inválido") from None
    if not isinstance(header, dict):
        raise ProtocolError("cabeçalho inválido")
    raw += await reader.readexactly(body_len)
    return bytes(raw)  # a única cópia do PDF no servidor


async def _discard_input(reader: asyncio.StreamReader) -> None:
    """Lê e descarta o que o cliente ainda está mandando, para ele terminar o envio e ler a resposta.

    Sem isso, um cliente mandando um PDF maior que o buffer do socket recebe EPIPE
    no envio e nunca lê o BUSY. Em pedaços pequenos e com prazo: nada fica em memória.
    """
    with contextlib.suppress(TimeoutError, ConnectionError):
        async with asyncio.timeout(READ_TIMEOUT_SECONDS):
            while await reader.read(64 * 1024):
                pass


async def _run_task(raw_request: bytes) -> bytes:
    try:
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-E",
            "-s",
            "-m",
            "pdf_worker.task",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env=TASK_ENV,
            preexec_fn=_limit_task,  # noqa: PLW1509 - processo de um único pedido, sem threads no filho
            start_new_session=True,
        )
    except (OSError, subprocess.SubprocessError):
        # Sem processo não há isolamento: nunca processar o PDF aqui no servidor.
        logger.exception("não foi possível criar o processo da tarefa")
        return error(ERR_INTERNAL)
    try:
        output, _ = await asyncio.wait_for(process.communicate(raw_request), TASK_TIMEOUT_SECONDS)
    except TimeoutError:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        await process.wait()
        logger.warning("tarefa encerrada por tempo")
        return error(ERR_TIMEOUT)
    if process.returncode != 0:
        logger.warning("tarefa terminou com código %s", process.returncode)
        return error(ERR_UNPROCESSABLE)
    try:
        decode(reader_from_bytes(output))
    except ProtocolError:
        return error(ERR_UNPROCESSABLE)
    return output


async def _handle(
    semaphore: asyncio.Semaphore, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    try:
        # A vaga é pega ANTES de ler: no máximo MAX_CONCURRENT_TASKS PDFs em memória.
        # Quem espera demais recebe BUSY (a API responde 429 com Retry-After).
        try:
            await asyncio.wait_for(semaphore.acquire(), QUEUE_TIMEOUT_SECONDS)
        except TimeoutError:
            writer.write(error(ERR_BUSY))
            await _discard_input(reader)
            return
        try:
            try:
                raw_request = await asyncio.wait_for(_read_request(reader), READ_TIMEOUT_SECONDS)
            except (ProtocolError, asyncio.IncompleteReadError, TimeoutError):
                writer.write(error(ERR_BAD_REQUEST))
                return
            try:
                response = await _run_task(raw_request)
            except Exception:  # noqa: BLE001 - a API sempre recebe uma resposta no formato
                logger.exception("falha inesperada no servidor do worker")
                response = error(ERR_INTERNAL)
            del raw_request
            writer.write(response)
        finally:
            semaphore.release()
    finally:
        with contextlib.suppress(ConnectionError):
            await writer.drain()
        writer.close()


async def serve() -> None:
    with contextlib.suppress(FileNotFoundError):
        os.unlink(SOCKET_PATH)
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_TASKS)
    server = await asyncio.start_unix_server(partial(_handle, semaphore), path=SOCKET_PATH)
    # Só o dono (worker) e o grupo compartilhado com a API conseguem conectar.
    os.chmod(SOCKET_PATH, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)
    logger.info("pdf-worker ouvindo em %s", SOCKET_PATH)
    async with server:
        await server.serve_forever()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    asyncio.run(serve())


if __name__ == "__main__":
    main()
