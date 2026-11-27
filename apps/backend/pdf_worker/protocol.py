"""Protocolo entre a API e o pdf-worker (REQ-62).

Uma conexão leva um pedido e volta uma resposta, os dois no mesmo formato:

    b"SDW1" | tamanho do cabeçalho (4 bytes, big-endian) | cabeçalho JSON
           | tamanho do corpo (8 bytes, big-endian)      | corpo (bytes do PDF)

Pedido:   {"op": "inspect", "args": {...}}                 + PDF
Resposta: {"ok": true, "result": {...}}                    + bytes devolvidos (se houver)
          {"ok": false, "error": "HAS_JAVASCRIPT" | ...}   + nada

Os dois lados conferem os limites antes de alocar memória: um cabeçalho ou
corpo declarado grande demais é recusado sem ser lido.

Este módulo só usa a biblioteca padrão: é importado pela API e pelo worker.
"""

import json
import struct
from collections.abc import Callable
from typing import Any

MAGIC = b"SDW1"
# Cabe a resposta do inspect com o máximo de páginas (ops.MAX_PAGES x ~45 bytes por página).
MAX_HEADER_BYTES = 512 * 1024
# Teto do worker. O limite de verdade do upload (MAX_UPLOAD_MB, até 100) é aplicado na API.
MAX_BODY_BYTES = 128 * 1024 * 1024

# Erros que o worker pode devolver (o cliente da API traduz para o ErrorCode).
ERR_BAD_REQUEST = "BAD_REQUEST"
ERR_UNPROCESSABLE = "UNPROCESSABLE"
ERR_HAS_JAVASCRIPT = "HAS_JAVASCRIPT"
ERR_INVALID_POSITION = "INVALID_POSITION"
ERR_ALREADY_SIGNED = "ALREADY_SIGNED"  # quem assina já tem uma assinatura válida do SaferDocs no PDF
ERR_TIMEOUT = "TIMEOUT"
ERR_BUSY = "BUSY"  # todas as vagas ocupadas: tente de novo em instantes
ERR_INTERNAL = "INTERNAL"


class ProtocolError(Exception):
    """Mensagem fora do formato, truncada ou acima dos limites."""


def encode(header: dict[str, Any], body: bytes = b"") -> bytes:
    raw_header = json.dumps(header, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if len(raw_header) > MAX_HEADER_BYTES:
        raise ProtocolError("cabeçalho grande demais")
    if len(body) > MAX_BODY_BYTES:
        raise ProtocolError("corpo grande demais")
    return MAGIC + struct.pack(">I", len(raw_header)) + raw_header + struct.pack(">Q", len(body)) + body


def decode(
    read_exact: Callable[[int], bytes], *, max_body: int = MAX_BODY_BYTES
) -> tuple[dict[str, Any], bytes]:
    """Lê uma mensagem usando `read_exact(n)`, que devolve exatamente n bytes ou levanta ProtocolError."""
    if read_exact(len(MAGIC)) != MAGIC:
        raise ProtocolError("formato desconhecido")
    (header_len,) = struct.unpack(">I", read_exact(4))
    if header_len > MAX_HEADER_BYTES:
        raise ProtocolError("cabeçalho grande demais")
    try:
        header = json.loads(read_exact(header_len))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProtocolError("cabeçalho inválido") from None
    if not isinstance(header, dict):
        raise ProtocolError("cabeçalho inválido")
    (body_len,) = struct.unpack(">Q", read_exact(8))
    if body_len > min(max_body, MAX_BODY_BYTES):
        raise ProtocolError("corpo grande demais")
    body = read_exact(body_len) if body_len else b""
    return header, body


def reader_from_bytes(data: bytes) -> Callable[[int], bytes]:
    """`read_exact` sobre bytes já em memória (usado pelo processo de cada tarefa)."""
    view = memoryview(data)
    position = 0

    def read_exact(n: int) -> bytes:
        nonlocal position
        if position + n > len(view):
            raise ProtocolError("mensagem truncada")
        chunk = bytes(view[position : position + n])
        position += n
        return chunk

    return read_exact


def reader_from_socket(sock: Any) -> Callable[[int], bytes]:
    """`read_exact` sobre um socket bloqueante (usado pelo cliente da API)."""

    def read_exact(n: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < n:
            chunk = sock.recv(min(n - len(chunks), 1024 * 1024))
            if not chunk:
                raise ProtocolError("conexão encerrada no meio da mensagem")
            chunks += chunk
        return bytes(chunks)

    return read_exact


# Selo de assinatura (REQ-47/49): tamanho fixo, em pontos PDF; (x, y) é o canto
# inferior esquerdo, com a origem embaixo à esquerda da página. Usado pela API
# para validar a posição e pelo worker para desenhar.
SEAL_WIDTH = 240
SEAL_HEIGHT = 80
MAX_SEAL_LINES = 6
MAX_SEAL_LINE_LENGTH = 100


def error(code: str) -> bytes:
    return encode({"ok": False, "error": code})
