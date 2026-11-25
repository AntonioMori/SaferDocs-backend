"""Cliente do pdf-worker isolado (REQ-62).

Todo parsing de PDF acontece no worker, sem rede e sem segredos. A chave
privada do usuário NUNCA vai para o worker: ele prepara o documento e
devolve o digest; a API assina o digest e manda só o CMS de volta.

    info = inspect(pdf)                       # páginas e tamanhos; recusa PDF inválido
    prepared = prepare_sign(pdf, page=1, x=400, y=50, seal_lines=[...], signer_cert_pem=cert)
    cms = <API assina prepared.digest com a chave do usuário>
    signed_pdf = finish_sign(prepared.prepared_pdf, cms)   # na API, sem o worker
    result = verify(pdf)

A conversa é por socket Unix (`PDF_WORKER_SOCKET`), com o protocolo de
`pdf_worker/protocol.py` e o timeout `PDF_WORKER_TIMEOUT_SECONDS`. Erros do
worker viram AppError:

- PDF corrompido, protegido por senha ou que estoura tempo/memória:
  ErrorCode.DOC_UNPROCESSABLE (400);
- JavaScript embutido: ErrorCode.DOC_HAS_JAVASCRIPT (400, REQ-63);
- posição do selo fora da página: ErrorCode.DOC_INVALID_POSITION (400);
- worker ocupado (todas as vagas em uso além do prazo da fila):
  ErrorCode.RATE_LIMITED (429) com `Retry-After`;
- worker fora do ar ou resposta inválida: ErrorCode.INTERNAL (500).

As funções são síncronas (socket bloqueante, até PDF_WORKER_TIMEOUT_SECONDS).
Numa rota `async def`, chame com `await run_in_threadpool(inspect, pdf)` para
não travar o event loop; numa rota `def` o FastAPI já usa o threadpool.

O worker faz `inspect`, `prepare_sign` e `verify`. O que ele devolve em
`prepare_sign` é conferido aqui (`app/pdf/signature_bytes.py`): o original
intacto no começo, o /ByteRange cobrindo o arquivo e o digest recalculado pela
API. O `finish_sign` (escrever o CMS no /Contents) é só troca de bytes e roda
na API: o arquivo assinado não passa pelo worker depois de assinado.
"""

import base64
import logging
import socket
from dataclasses import dataclass
from typing import Any

from app.core.config import get_settings
from app.core.errors import AppError, ErrorCode
from app.pdf.signature_bytes import SignatureBytesError, check_prepared, embed_cms, reserved_contents
from pdf_worker import protocol

logger = logging.getLogger("saferdocs.pdf")

BUSY_RETRY_AFTER_SECONDS = 5

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
    digest: bytes  # SHA-256 dos bytes cobertos pelo ByteRange, recalculado pela API


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
            try:
                sock.sendall(protocol.encode({"op": op, "args": args}, pdf))
                sock.shutdown(socket.SHUT_WR)
            except (BrokenPipeError, ConnectionResetError):
                # O worker pode responder (ex.: BUSY) e fechar antes de receber o PDF todo.
                # A resposta já está no buffer: lê assim mesmo.
                pass
            header, body = protocol.decode(protocol.reader_from_socket(sock))
    except (OSError, protocol.ProtocolError) as exc:
        # Só o tipo do erro vai para o log: nada do PDF nem do caminho interno do erro.
        logger.error("pdf-worker indisponível ou resposta inválida (%s)", type(exc).__name__)
        raise AppError(ErrorCode.INTERNAL) from None

    if header.get("ok") is True and isinstance(header.get("result"), dict):
        return header["result"], body
    if header.get("error") == protocol.ERR_BUSY:
        raise AppError(ErrorCode.RATE_LIMITED, headers={"Retry-After": str(BUSY_RETRY_AFTER_SECONDS)})
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
    """Worker: desenha o selo, reserva o /Contents e devolve o digest a assinar (REQ-46).

    A chave privada não vai para o worker: só o certificado (público) do assinante.
    """
    args = {
        "page": page,
        "x": x,
        "y": y,
        "seal_lines": seal_lines,
        "signer_cert_pem": signer_cert_pem.decode("ascii"),
    }
    result, prepared_pdf = _call("prepare_sign", args, pdf)
    try:
        worker_digest = bytes.fromhex(result["digest"])
        _, digest = check_prepared(pdf, prepared_pdf)
    except (KeyError, TypeError, ValueError) as exc:
        # SignatureBytesError é ValueError: preparado sem o original no começo, sem /ByteRange
        # cobrindo o arquivo ou com /Contents já preenchido.
        logger.error("pdf-worker devolveu um prepare_sign fora do formato (%s)", type(exc).__name__)
        raise AppError(ErrorCode.INTERNAL) from None
    if worker_digest != digest:
        logger.error("pdf-worker devolveu um digest que não é o dos bytes preparados")
        raise AppError(ErrorCode.INTERNAL)
    return PreparedSignature(prepared_pdf=prepared_pdf, digest=digest)


def finish_sign(prepared_pdf: bytes, cms: bytes) -> bytes:
    """Escreve o CMS no /Contents reservado do PDF preparado (REQ-46). Roda na API, sem o worker."""
    try:
        return embed_cms(prepared_pdf, reserved_contents(prepared_pdf), cms)
    except SignatureBytesError:
        logger.error("PDF preparado ou CMS fora do formato ao finalizar a assinatura")
        raise AppError(ErrorCode.INTERNAL) from None


def verify(pdf: bytes) -> VerificationResult:
    """Worker: confere a assinatura embutida mais recente (REQ-50). Não regrava o PDF."""
    result, _ = _call("verify", {}, pdf)
    try:
        key_b64 = result["signer_public_key_der"]
        return VerificationResult(
            has_signature=result["has_signature"] is True,
            cms_valid=result["cms_valid"] is True,
            covers_whole_file=result["covers_whole_file"] is True,
            signer_public_key_der=base64.b64decode(key_b64, validate=True) if key_b64 else None,
            signature_id=None,  # o id vem do registro no banco (REQ-51)
        )
    except (KeyError, TypeError, ValueError):
        logger.error("pdf-worker devolveu um verify fora do formato")
        raise AppError(ErrorCode.INTERNAL) from None
