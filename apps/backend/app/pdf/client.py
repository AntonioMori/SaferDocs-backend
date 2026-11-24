"""Cliente do pdf-worker isolado (REQ-62).

Todo parsing de PDF acontece no worker, sem rede e sem segredos. A chave
privada do usuário NUNCA vai para o worker: ele prepara o documento e
devolve o digest; a API assina o digest e manda só o CMS de volta.

    info = inspect(pdf)                       # páginas e tamanhos; recusa PDF inválido
    prepared = prepare_sign(pdf, page=1, x=400, y=50, seal_lines=[...], signer_cert_pem=cert)
    cms = <API assina prepared.digest com a chave do usuário>
    signed_pdf = finish_sign(prepared.prepared_pdf, cms)
    result = verify(pdf)

A conversa é por socket Unix (`PDF_WORKER_SOCKET`), com o protocolo de
`pdf_worker/protocol.py` e o timeout `PDF_WORKER_TIMEOUT_SECONDS`. Erros do
worker viram AppError:

- PDF corrompido, protegido por senha ou que estoura tempo/memória:
  ErrorCode.DOC_UNPROCESSABLE (400);
- JavaScript embutido: ErrorCode.DOC_HAS_JAVASCRIPT (400, REQ-63);
- posição do selo fora da página: ErrorCode.DOC_INVALID_POSITION (400);
- worker fora do ar ou resposta inválida: ErrorCode.INTERNAL (500).

`prepare_sign`, `finish_sign` e `verify` ainda são stubs depois do `inspect`;
a implementação real entra com o REQ-46 e o REQ-50 (dono: v1ct0rjoao).
"""

import logging
import socket
from dataclasses import dataclass
from typing import Any

from app.core.config import get_settings
from app.core.errors import AppError, ErrorCode
from pdf_worker import protocol

logger = logging.getLogger("saferdocs.pdf")

_WORKER_ERRORS = {
    protocol.ERR_UNPROCESSABLE: ErrorCode.DOC_UNPROCESSABLE,
    protocol.ERR_TIMEOUT: ErrorCode.DOC_UNPROCESSABLE,
    protocol.ERR_HAS_JAVASCRIPT: ErrorCode.DOC_HAS_JAVASCRIPT,
    protocol.ERR_INVALID_POSITION: ErrorCode.DOC_INVALID_POSITION,
}


@dataclass(frozen=True)
class PageSize:
    width: float
    height: float


@dataclass(frozen=True)
class PdfInfo:
    page_count: int
    pages: list[PageSize]


@dataclass(frozen=True)
class PreparedSignature:
    prepared_pdf: bytes  # PDF com o selo desenhado e o espaço reservado para a assinatura
    digest: bytes  # SHA-256 dos bytes cobertos pelo ByteRange, a ser assinado pela API


@dataclass(frozen=True)
class VerificationResult:
    has_signature: bool  # há assinatura embutida (ISO 32000)?
    cms_valid: bool  # o CMS confere com o conteúdo coberto?
    covers_whole_file: bool  # a assinatura cobre o arquivo inteiro (sem alteração incremental)?
    signer_public_key_der: bytes | None  # chave pública do certificado do assinante
    signature_id: str | None  # id da assinatura lido do documento, se houver


def _connect(path: str, timeout: float) -> socket.socket:
    """Abre a conexão com o worker. Substituído nos testes."""
    family = getattr(socket, "AF_UNIX", None)
    if family is None:
        raise OSError("socket Unix indisponível nesta plataforma; rode a API com o docker compose")
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(path)
    except OSError:
        sock.close()
        raise
    return sock


def _call(op: str, args: dict[str, Any], pdf: bytes) -> tuple[dict[str, Any], bytes]:
    settings = get_settings()
    try:
        with _connect(settings.pdf_worker_socket, settings.pdf_worker_timeout_seconds) as sock:
            sock.sendall(protocol.encode({"op": op, "args": args}, pdf))
            sock.shutdown(socket.SHUT_WR)
            header, body = protocol.decode(protocol.reader_from_socket(sock))
    except (OSError, protocol.ProtocolError) as exc:
        # Só o tipo do erro vai para o log: nada do PDF nem do caminho interno do erro.
        logger.error("pdf-worker indisponível ou resposta inválida (%s)", type(exc).__name__)
        raise AppError(ErrorCode.INTERNAL) from None

    if header.get("ok") is True and isinstance(header.get("result"), dict):
        return header["result"], body
    code = _WORKER_ERRORS.get(header.get("error"))  # type: ignore[arg-type]
    if code is None:
        logger.error("pdf-worker devolveu erro %r em %s", header.get("error"), op)
        raise AppError(ErrorCode.INTERNAL)
    raise AppError(code)


def inspect(pdf: bytes) -> PdfInfo:
    """Abre o PDF no worker e devolve as páginas. Recusa PDF que não dá para processar."""
    result, _ = _call("inspect", {}, pdf)
    try:
        pages = [PageSize(float(p["width"]), float(p["height"])) for p in result["pages"]]
        return PdfInfo(page_count=int(result["page_count"]), pages=pages)
    except (KeyError, TypeError, ValueError):
        logger.error("pdf-worker devolveu um inspect fora do formato")
        raise AppError(ErrorCode.INTERNAL) from None


def prepare_sign(
    pdf: bytes, *, page: int, x: float, y: float, seal_lines: list[str], signer_cert_pem: bytes
) -> PreparedSignature:
    inspect(pdf)  # REQ-62/63: o PDF passa pelo worker antes de qualquer outra coisa
    del page, x, y, seal_lines, signer_cert_pem  # STUB até o REQ-46
    return PreparedSignature(prepared_pdf=pdf, digest=b"\x00" * 32)


def finish_sign(prepared_pdf: bytes, cms: bytes) -> bytes:
    del cms  # STUB até o REQ-46
    return prepared_pdf


def verify(pdf: bytes) -> VerificationResult:
    inspect(pdf)  # REQ-62/63: o PDF passa pelo worker antes de qualquer outra coisa
    return VerificationResult(  # STUB até o REQ-50
        has_signature=False,
        cms_valid=False,
        covers_whole_file=False,
        signer_public_key_der=None,
        signature_id=None,
    )
