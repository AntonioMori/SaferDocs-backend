"""Operações do worker sobre o PDF. Só este módulo faz parsing (pikepdf).

Cada operação recebe os bytes do PDF e os argumentos do pedido e devolve
`(resultado, bytes)`. Falhas viram `OpError` com um código do protocolo, sem
detalhes do parser (que poderiam vazar conteúdo do documento).

Operações: `inspect`, `prepare_sign` (REQ-46) e `verify` (REQ-50). Escrever o
CMS no /Contents não passa por aqui: a API faz isso depois de conferir o preparado.
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


def _inherited(page: pikepdf.Dictionary, key: str) -> Any:
    """Valor de `key` na página ou no ancestral mais próximo (MediaBox, CropBox e Rotate são herdáveis)."""
    node: Any = page
    for _ in range(MAX_TREE_DEPTH):
        if not isinstance(node, pikepdf.Dictionary):
            return None
        value = node.get(key)
        if value is not None:
            return value
        node = node.get("/Parent")
    return None


def _rectangle(box: Any) -> tuple[float, float, float, float] | None:
    """(x0, y0, x1, y1) normalizado de um retângulo PDF, ou None se não for um retângulo com área."""
    if not isinstance(box, pikepdf.Array) or len(box) != 4:
        return None
    values = [box[i] for i in range(4)]
    if not all(isinstance(v, int | Decimal | float) and not isinstance(v, bool) for v in values):
        return None
    x0, y0, x1, y1 = (float(v) for v in values)
    left, bottom, right, top = min(x0, x1), min(y0, y1), max(x0, x1), max(y0, y1)
    if not (0 < right - left <= MAX_PAGE_POINTS and 0 < top - bottom <= MAX_PAGE_POINTS):
        return None
    return left, bottom, right, top


def _page_box(page: pikepdf.Dictionary) -> tuple[float, float, float, float]:
    """Canto inferior esquerdo, largura e altura da área VISÍVEL da página (REQ-49).

    É o /MediaBox recortado pelo /CropBox, como os leitores de PDF mostram: um
    selo fora do CropBox ficaria invisível. O `page.mediabox` do pikepdf devolve
    612x792 quando a caixa falta ou é inválida; um tamanho inventado poria o
    selo no lugar errado, então sem MediaBox válido o PDF não é processável.
    Um CropBox inválido é ignorado (a norma manda usar o MediaBox).
    """
    media = _rectangle(_inherited(page, "/MediaBox"))
    if media is None:
        raise OpError(ERR_UNPROCESSABLE)
    crop = _rectangle(_inherited(page, "/CropBox"))
    left, bottom, right, top = media
    if crop is not None:
        left, bottom = max(left, crop[0]), max(bottom, crop[1])
        right, top = min(right, crop[2]), min(top, crop[3])
        if right <= left or top <= bottom:
            raise OpError(ERR_UNPROCESSABLE)  # CropBox fora da página: nada é visível
    return left, bottom, right - left, top - bottom


def _page_rotation(page: pikepdf.Dictionary) -> int:
    """/Rotate da página (0, 90, 180 ou 270); valor que não é múltiplo de 90 é ignorado, como nos leitores."""
    value = _inherited(page, "/Rotate")
    if isinstance(value, bool) or not isinstance(value, int) or value % 90:
        return 0
    return int(value) % 360


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
                pages.append(
                    {
                        "width": width,
                        "height": height,
                        "left": left,
                        "bottom": bottom,
                        "rotate": _page_rotation(page.obj),
                    }
                )
            # Ao ler a árvore de páginas, o qpdf troca um MediaBox ausente ou inválido por
            # 612x792 no próprio objeto e só avisa. Um tamanho inventado não serve (REQ-49).
            warnings += document.get_warnings()
            if any("mediabox" in warning.lower() for warning in warnings):
                raise OpError(ERR_UNPROCESSABLE)
        except (pikepdf.PdfError, ValueError, TypeError, KeyError):
            raise OpError(ERR_UNPROCESSABLE) from None
    return pages


def inspect(pdf: bytes, args: dict[str, Any]) -> tuple[dict[str, Any], bytes]:
    """Abre o PDF e devolve a área visível e a rotação de cada página (para posicionar o selo).

    A posição (x, y) do selo é sempre no sistema da página sem rotação, a partir do
    canto inferior esquerdo da área visível; `rotate` diz como o leitor gira a página.
    """
    del args
    pages = [{"width": p["width"], "height": p["height"], "rotate": p["rotate"]} for p in page_sizes(pdf)]
    return {"page_count": len(pages), "pages": pages}, b""


def _operations() -> dict[str, Callable[[bytes, dict[str, Any]], tuple[dict[str, Any], bytes]]]:
    from pdf_worker import sign  # importa o pyHanko só quando a operação é de assinatura

    return {
        "inspect": inspect,
        "prepare_sign": sign.prepare_sign,
        "verify": sign.verify,
    }


OPERATIONS: dict[str, Callable[[bytes, dict[str, Any]], tuple[dict[str, Any], bytes]]] = {"inspect": inspect}


def run(op: Any, args: Any, pdf: bytes) -> tuple[dict[str, Any], bytes]:
    if not isinstance(op, str) or not isinstance(args, dict):
        raise OpError(ERR_BAD_REQUEST)
    operation = OPERATIONS.get(op) or _operations().get(op)
    if operation is None:
        raise OpError(ERR_BAD_REQUEST)
    return operation(pdf, args)
