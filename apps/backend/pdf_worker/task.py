"""Processo de uma única tarefa: `python -m pdf_worker.task`.

Lê um pedido do stdin, executa a operação e escreve a resposta no stdout.
O servidor cria um processo destes por pedido, com limites do sistema
(`server.py`). Se o parser travar ou estourar a memória com um PDF
malicioso, morre só este processo.
"""

import sys
from typing import Any

from pdf_worker.ops import OpError, run
from pdf_worker.protocol import (
    ERR_BAD_REQUEST,
    ERR_INTERNAL,
    ERR_UNPROCESSABLE,
    ProtocolError,
    decode,
    encode,
    error,
    reader_from_bytes,
)


def handle(raw_request: bytes) -> bytes:
    """Pedido completo (bytes) -> resposta completa (bytes). Nunca levanta exceção."""
    try:
        header, pdf = decode(reader_from_bytes(raw_request))
    except ProtocolError:
        return error(ERR_BAD_REQUEST)
    try:
        result, body = run(header.get("op"), header.get("args", {}), pdf)
        response: dict[str, Any] = {"ok": True, "result": result}
        return encode(response, body)
    except OpError as exc:
        return error(exc.code)
    except MemoryError:
        # Bateu no limite de memória da tarefa (RLIMIT_AS): o PDF é pesado demais para processar.
        return error(ERR_UNPROCESSABLE)
    except Exception:  # noqa: BLE001 - qualquer outra falha vira INTERNAL, sem detalhes do PDF
        return error(ERR_INTERNAL)


def main() -> None:
    raw_request = sys.stdin.buffer.read()
    sys.stdout.buffer.write(handle(raw_request))
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
