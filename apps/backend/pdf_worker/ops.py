"""Operações do worker sobre o PDF. Só este módulo faz parsing (pikepdf).

Cada operação recebe os bytes do PDF e os argumentos do pedido e devolve
`(resultado, bytes)`. Falhas viram `OpError` com um código do protocolo, sem
detalhes do parser (que poderiam vazar conteúdo do documento).

Hoje só existe `inspect`. As operações de assinatura e verificação
(`prepare_sign`, `finish_sign`, `verify`) entram com o REQ-46 e o REQ-50.
"""

import io
from collections.abc import Callable
from typing import Any

import pikepdf

from pdf_worker.protocol import ERR_BAD_REQUEST, ERR_UNPROCESSABLE

MAX_PAGES = 5000


class OpError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def open_pdf(pdf: bytes) -> pikepdf.Pdf:
    """Abre o PDF em memória. PDF corrompido ou protegido por senha não é processável."""
    try:
        return pikepdf.open(io.BytesIO(pdf))
    except (pikepdf.PdfError, pikepdf.PasswordError, ValueError, OSError):
        raise OpError(ERR_UNPROCESSABLE) from None


def inspect(pdf: bytes, args: dict[str, Any]) -> tuple[dict[str, Any], bytes]:
    """Abre o PDF e devolve o tamanho de cada página (usado para validar a posição do selo)."""
    del args
    with open_pdf(pdf) as document:
        try:
            if len(document.pages) == 0 or len(document.pages) > MAX_PAGES:
                raise OpError(ERR_UNPROCESSABLE)
            pages = []
            for page in document.pages:
                x0, y0, x1, y1 = (float(v) for v in page.mediabox)
                pages.append({"width": abs(x1 - x0), "height": abs(y1 - y0)})
        except (pikepdf.PdfError, ValueError, TypeError, KeyError):
            raise OpError(ERR_UNPROCESSABLE) from None
    return {"page_count": len(pages), "pages": pages}, b""


OPERATIONS: dict[str, Callable[[bytes, dict[str, Any]], tuple[dict[str, Any], bytes]]] = {
    "inspect": inspect,
}


def run(op: Any, args: Any, pdf: bytes) -> tuple[dict[str, Any], bytes]:
    if not isinstance(op, str) or op not in OPERATIONS or not isinstance(args, dict):
        raise OpError(ERR_BAD_REQUEST)
    return OPERATIONS[op](pdf, args)
