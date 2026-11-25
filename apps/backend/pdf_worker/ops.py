"""Operações do worker sobre o PDF. Só este módulo faz parsing (pikepdf).

Cada operação recebe os bytes do PDF e os argumentos do pedido e devolve
`(resultado, bytes)`. Falhas viram `OpError` com um código do protocolo, sem
detalhes do parser (que poderiam vazar conteúdo do documento).

Hoje só existe `inspect`. As operações de assinatura e verificação
(`prepare_sign`, `finish_sign`, `verify`) entram com o REQ-46 e o REQ-50.
"""

import io
from collections.abc import Callable
from decimal import Decimal
from typing import Any

import pikepdf

from pdf_worker.protocol import ERR_BAD_REQUEST, ERR_HAS_JAVASCRIPT, ERR_UNPROCESSABLE
from pdf_worker.validate import DamagedPdfError, has_javascript, has_javascript_in_rebuilt

MAX_PAGES = 5000
MAX_TREE_DEPTH = 64  # níveis de /Parent subindo da página até a raiz
MAX_PAGE_POINTS = 14400  # maior página que o PDF permite (200 polegadas)


class OpError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def open_pdf(pdf: bytes) -> tuple[pikepdf.Pdf, list[str]]:
    """Abre o PDF em memória e recusa JavaScript (REQ-63). Toda operação começa aqui.

    PDF corrompido ou protegido por senha não é processável. Devolve também os
    avisos do qpdf lidos na varredura (o pikepdf limpa a lista a cada leitura).
    """
    scan_errors = (pikepdf.PdfError, ValueError, TypeError, RecursionError, DamagedPdfError)
    try:
        if has_javascript_in_rebuilt(pdf):  # antes de abrir o principal: uma cópia por vez
            raise OpError(ERR_HAS_JAVASCRIPT)
    except scan_errors:
        raise OpError(ERR_UNPROCESSABLE) from None
    try:
        document = pikepdf.open(io.BytesIO(pdf))
    except (pikepdf.PdfError, pikepdf.PasswordError, ValueError, OSError):
        raise OpError(ERR_UNPROCESSABLE) from None
    try:
        javascript, warnings = has_javascript(document)
    except scan_errors:
        document.close()
        raise OpError(ERR_UNPROCESSABLE) from None
    if javascript:
        document.close()
        raise OpError(ERR_HAS_JAVASCRIPT)
    return document, warnings


def _page_box(page: pikepdf.Dictionary) -> tuple[float, float, float, float]:
    """Canto inferior esquerdo, largura e altura do /MediaBox, herdado dos ancestrais se preciso.

    O `page.mediabox` do pikepdf devolve 612x792 quando a caixa falta ou é
    inválida; um tamanho inventado poria o selo no lugar errado (REQ-49).
    Sem uma caixa de 4 números com área positiva, o PDF não é processável.
    """
    node: Any = page
    for _ in range(MAX_TREE_DEPTH):
        if not isinstance(node, pikepdf.Dictionary):
            break
        box = node.get("/MediaBox")
        if box is not None:
            if not isinstance(box, pikepdf.Array) or len(box) != 4:
                raise OpError(ERR_UNPROCESSABLE)
            values = [box[i] for i in range(4)]
            if not all(isinstance(v, int | Decimal | float) and not isinstance(v, bool) for v in values):
                raise OpError(ERR_UNPROCESSABLE)
            x0, y0, x1, y1 = (float(v) for v in values)
            width, height = abs(x1 - x0), abs(y1 - y0)
            if not (0 < width <= MAX_PAGE_POINTS and 0 < height <= MAX_PAGE_POINTS):
                raise OpError(ERR_UNPROCESSABLE)
            return min(x0, x1), min(y0, y1), width, height
        node = node.get("/Parent")
    raise OpError(ERR_UNPROCESSABLE)


def page_sizes(pdf: bytes) -> list[dict[str, float]]:
    """Abre o PDF (com a recusa de JavaScript) e devolve largura e altura de cada página."""
    document, warnings = open_pdf(pdf)
    with document:
        try:
            if len(document.pages) == 0 or len(document.pages) > MAX_PAGES:
                raise OpError(ERR_UNPROCESSABLE)
            pages = []
            for page in document.pages:
                left, bottom, width, height = _page_box(page.obj)
                pages.append({"width": width, "height": height, "left": left, "bottom": bottom})
            # Ao ler a árvore de páginas, o qpdf troca um MediaBox ausente ou inválido por
            # 612x792 no próprio objeto e só avisa. Um tamanho inventado não serve (REQ-49).
            warnings += document.get_warnings()
            if any("mediabox" in warning.lower() for warning in warnings):
                raise OpError(ERR_UNPROCESSABLE)
        except (pikepdf.PdfError, ValueError, TypeError, KeyError):
            raise OpError(ERR_UNPROCESSABLE) from None
    return pages


def inspect(pdf: bytes, args: dict[str, Any]) -> tuple[dict[str, Any], bytes]:
    """Abre o PDF e devolve o tamanho de cada página (usado para validar a posição do selo)."""
    del args
    pages = [{"width": p["width"], "height": p["height"]} for p in page_sizes(pdf)]
    return {"page_count": len(pages), "pages": pages}, b""


def _operations() -> dict[str, Callable[[bytes, dict[str, Any]], tuple[dict[str, Any], bytes]]]:
    from pdf_worker import sign  # importa o pyHanko só quando a operação é de assinatura

    return {
        "inspect": inspect,
        "prepare_sign": sign.prepare_sign,
        "finish_sign": sign.finish_sign,
    }


OPERATIONS: dict[str, Callable[[bytes, dict[str, Any]], tuple[dict[str, Any], bytes]]] = {"inspect": inspect}


def run(op: Any, args: Any, pdf: bytes) -> tuple[dict[str, Any], bytes]:
    if not isinstance(op, str) or not isinstance(args, dict):
        raise OpError(ERR_BAD_REQUEST)
    operation = OPERATIONS.get(op) or _operations().get(op)
    if operation is None:
        raise OpError(ERR_BAD_REQUEST)
    return operation(pdf, args)
