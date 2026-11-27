"""Aparência do selo de assinatura (REQ-47), desenhada em operadores PDF.

    ┌──────┬──────────────────────────────────┐
    │      │ ASSINADO DIGITALMENTE            │
    │  S•  │ Nome de quem assinou             │   faixa azul da marca com o monograma
    │      │ 27/11/2026 · 04:16:29 UTC        │   e o ponto âmbar (o "lacre"); à direita
    │      │ ──────────────────────────────── │   o destaque, a data e, em letra pequena,
    │      │ SHA-256 44e1808f…f9fc5418        │   o hash abreviado e o id
    │      │ ID 8d473815-67cb-4b80-...        │
    └──────┴──────────────────────────────────┘

As linhas vêm da API em ordem: a 1ª é o destaque (o nome), a 2ª a linha de apoio (a data) e as
demais o rodapé em letra mono. O texto usa as fontes padrão do PDF (Helvetica e Courier, WinAnsi),
que todo leitor tem: nada é embutido no arquivo.
"""

from typing import Any

from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.content import PdfResources, RawContent
from pyhanko.pdf_utils.layout import AxisAlignment, BoxConstraints, InnerScaling, SimpleBoxLayoutRule
from pyhanko.stamp import TextStampStyle

from pdf_worker.ops import OpError
from pdf_worker.protocol import ERR_BAD_REQUEST, MAX_SEAL_LINE_LENGTH, MAX_SEAL_LINES, SEAL_HEIGHT, SEAL_WIDTH

EYEBROW = "ASSINADO DIGITALMENTE"

# Paleta (RGB 0-1): azul da marca, âmbar do lacre, tinta do texto e cinzas de apoio.
_BLUE = (0.027, 0.553, 0.933)  # #078DEE
_AMBER = (0.976, 0.686, 0.114)  # #F9AF1D
_INK = (0.110, 0.145, 0.180)  # #1C252E
_SUPPORT = (0.271, 0.310, 0.357)  # #454F5B
_MUTED = (0.388, 0.451, 0.506)  # #637381
_HAIRLINE = (0.875, 0.890, 0.910)  # #DFE3E8
_WHITE = (1.0, 1.0, 1.0)

_RADIUS = 6.0
_BAND = 52.0  # largura da faixa azul
_TEXT_X = _BAND + 10.0
_TEXT_RIGHT = SEAL_WIDTH - 9.0
_NAME_MAX_SIZE = 11.0
_NAME_MIN_SIZE = 6.5

# Larguras da Helvetica-Bold (AFM padrão, em 1/1000 em) para caber o nome sem cortar letra.
# O que não está na tabela (acentuadas etc.) usa a largura de uma minúscula média.
_HELVETICA_BOLD = dict(
    zip(
        " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",
        (
            278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278,
            556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611,
            975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778,
            667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556,
            333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611,
            611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584,
        ),
        strict=True,
    )
)  # fmt: skip
_DEFAULT_WIDTH = 611

# Monograma da marca (o "S" do logo), no desenho original de 104 x 104 com y para baixo.
_S_PATH = (
    (74, 30),
    ((68, 20), (30, 18), (30, 40)),
    ((30, 60), (74, 52), (74, 70)),
    ((74, 90), (36, 86), (28, 74)),
)
_S_CENTER = (51.0, 54.0)
_S_SCALE = 0.34
_S_STROKE = 11.0
_DOT = ((86.0, 86.0), 9.0)


def clean_lines(lines: Any) -> list[str]:
    """Valida as linhas da API e deixa só o que a fonte WinAnsi desenha (o resto vira "?")."""
    if not isinstance(lines, list) or not 1 <= len(lines) <= MAX_SEAL_LINES:
        raise OpError(ERR_BAD_REQUEST)
    clean = []
    for line in lines:
        if not isinstance(line, str) or len(line) > MAX_SEAL_LINE_LENGTH:
            raise OpError(ERR_BAD_REQUEST)
        text = "".join(c if c.isprintable() else " " for c in line)
        clean.append(text.encode("cp1252", errors="replace").decode("cp1252"))
    return clean


def _rgb(color: tuple[float, float, float], op: str) -> str:
    return f"{color[0]:.3f} {color[1]:.3f} {color[2]:.3f} {op}"


def _pdf_string(text: str) -> str:
    """String literal do PDF em WinAnsi, com os delimitadores e o resto não ASCII em octal."""
    out = []
    for byte in text.encode("cp1252", errors="replace"):
        char = chr(byte)
        if char in "()\\":
            out.append("\\" + char)
        elif 32 <= byte < 127:
            out.append(char)
        else:
            out.append(f"\\{byte:03o}")
    return "(" + "".join(out) + ")"


def _bold_width(text: str, size: float) -> float:
    return sum(_HELVETICA_BOLD.get(c, _DEFAULT_WIDTH) for c in text) * size / 1000


def _fit_name(name: str) -> tuple[str, float]:
    """Maior corpo (até 11 pt) em que o nome cabe; no mínimo, encurta com reticências."""
    room = _TEXT_RIGHT - _TEXT_X
    size = _NAME_MAX_SIZE
    while size > _NAME_MIN_SIZE and _bold_width(name, size) > room:
        size -= 0.25
    while len(name) > 1 and _bold_width(name, size) > room:
        name = name[:-2].rstrip() + "…"
    return name, size


def _rounded_rect(x: float, y: float, w: float, h: float, r: float) -> str:
    k = 0.5523 * r  # aproximação do quarto de círculo por Bézier
    return " ".join(
        [
            f"{x + r:.2f} {y:.2f} m",
            f"{x + w - r:.2f} {y:.2f} l",
            f"{x + w - r + k:.2f} {y:.2f} {x + w:.2f} {y + r - k:.2f} {x + w:.2f} {y + r:.2f} c",
            f"{x + w:.2f} {y + h - r:.2f} l",
            f"{x + w:.2f} {y + h - r + k:.2f} {x + w - r + k:.2f} {y + h:.2f} {x + w - r:.2f} {y + h:.2f} c",
            f"{x + r:.2f} {y + h:.2f} l",
            f"{x + r - k:.2f} {y + h:.2f} {x:.2f} {y + h - r + k:.2f} {x:.2f} {y + h - r:.2f} c",
            f"{x:.2f} {y + r:.2f} l",
            f"{x:.2f} {y + r - k:.2f} {x + r - k:.2f} {y:.2f} {x + r:.2f} {y:.2f} c",
            "h",
        ]
    )


def _circle(cx: float, cy: float, r: float) -> str:
    """Círculo como quatro Béziers, começando à direita e girando no sentido anti-horário."""
    k = 0.5523 * r
    quarters = (
        ((cx + r, cy + k), (cx + k, cy + r), (cx, cy + r)),
        ((cx - k, cy + r), (cx - r, cy + k), (cx - r, cy)),
        ((cx - r, cy - k), (cx - k, cy - r), (cx, cy - r)),
        ((cx + k, cy - r), (cx + r, cy - k), (cx + r, cy)),
    )
    curves = [" ".join(f"{x:.2f} {y:.2f}" for x, y in quarter) + " c" for quarter in quarters]
    return " ".join([f"{cx + r:.2f} {cy:.2f} m", *curves])


def _monogram(cx: float, cy: float) -> list[str]:
    """O "S" branco e o ponto âmbar, centrados em (cx, cy) na faixa azul."""
    s = _S_SCALE
    tx, ty = cx - _S_CENTER[0] * s, cy + _S_CENTER[1] * s  # y do desenho cresce para baixo

    def point(px: float, py: float) -> str:
        return f"{tx + px * s:.2f} {ty - py * s:.2f}"

    start, *curves = _S_PATH
    path = [f"{point(*start)} m"] + [" ".join(point(*p) for p in curve) + " c" for curve in curves]
    (dx, dy), dr = _DOT
    return [
        "q",
        _rgb(_WHITE, "RG"),
        f"{_S_STROKE * s:.2f} w 1 J 1 j",
        *path,
        "S",
        _rgb(_AMBER, "rg"),
        _circle(tx + dx * s, ty - dy * s, dr * s),
        "f",
        "Q",
    ]


def _text(font: str, size: float, x: float, y: float, color, text: str, spacing: float = 0) -> list[str]:
    return [
        "BT",
        f"/{font} {size:.2f} Tf",
        f"{spacing:.2f} Tc",
        _rgb(color, "rg"),
        f"{x:.2f} {y:.2f} Td",
        f"{_pdf_string(text)} Tj",
        "ET",
    ]


def _fonts() -> PdfResources:
    resources = PdfResources()
    for name, base in (("FB", "Helvetica-Bold"), ("FR", "Helvetica"), ("FM", "Courier")):
        resources.font[generic.NameObject(f"/{name}")] = generic.DictionaryObject(
            {
                generic.NameObject("/Type"): generic.NameObject("/Font"),
                generic.NameObject("/Subtype"): generic.NameObject("/Type1"),
                generic.NameObject("/BaseFont"): generic.NameObject(f"/{base}"),
                generic.NameObject("/Encoding"): generic.NameObject("/WinAnsiEncoding"),
            }
        )
    return resources


def appearance(lines: list[str]) -> RawContent:
    """Conteúdo do selo em 240 x 80 pt, a partir das linhas já limpas por `clean_lines`."""
    w, h = SEAL_WIDTH, SEAL_HEIGHT
    card = _rounded_rect(0.5, 0.5, w - 1, h - 1, _RADIUS)
    name, name_size = _fit_name(lines[0])
    ops = [
        # Cartão branco (cobre a página atrás: legível em qualquer fundo).
        _rgb(_WHITE, "rg"),
        f"{card} f",
        # Faixa azul, recortada pelo contorno arredondado do cartão.
        "q",
        f"{card} W n",
        _rgb(_BLUE, "rg"),
        f"0 0 {_BAND:.2f} {h:.2f} re f",
        "Q",
        *_monogram(_BAND / 2, h / 2),
        # Contorno fino por cima de tudo.
        _rgb(_HAIRLINE, "RG"),
        "0.75 w",
        f"{card} S",
        *_text("FB", 6.0, _TEXT_X, h - 17, _BLUE, EYEBROW, spacing=0.9),
        *_text("FB", name_size, _TEXT_X, h - 32, _INK, name),
    ]
    if len(lines) > 1:
        ops += _text("FR", 7.5, _TEXT_X, h - 43, _SUPPORT, lines[1])
    footer = lines[2:4]
    if footer:
        ops += [_rgb(_HAIRLINE, "RG"), "0.6 w", f"{_TEXT_X:.2f} 28.5 m {_TEXT_RIGHT:.2f} 28.5 l S"]
        for index, line in enumerate(footer):
            ops += _text("FM", 5.6, _TEXT_X, 18.5 - index * 8, _MUTED, line)
    return RawContent(
        "\n".join(ops).encode("ascii"), resources=_fonts(), box=BoxConstraints(width=w, height=h)
    )


def stamp_style(lines: list[str]) -> TextStampStyle:
    """Estilo do pyHanko que só desenha a nossa aparência: sem texto próprio e sem borda."""
    return TextStampStyle(
        stamp_text="",
        background=appearance(lines),
        background_layout=SimpleBoxLayoutRule(
            x_align=AxisAlignment.ALIGN_MID,
            y_align=AxisAlignment.ALIGN_MID,
            inner_content_scaling=InnerScaling.STRETCH_FILL,
        ),
        background_opacity=1,
        border_width=0,
    )
