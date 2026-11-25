"""Conferência, na API, do que o pdf-worker devolve na assinatura (REQ-46, REQ-59).

O worker lê PDFs de fora. Se um PDF malicioso o comprometesse, ele poderia
devolver o digest de OUTRO documento (e a API assinaria, com a chave do
usuário, algo que o usuário não mandou) ou um arquivo diferente do preparado.
Por isso a API não confia no worker:

- o PDF preparado começa com os bytes exatos do original (atualização incremental):
  o documento que o usuário mandou está intacto dentro do assinado;
- o /ByteRange da assinatura nova está na parte acrescentada e cobre o arquivo
  inteiro, menos o /Contents reservado (só zeros);
- o digest a assinar é recalculado aqui, sobre os bytes cobertos;
- o CMS é escrito aqui no /Contents: o arquivo assinado é o preparado com só
  essa região trocada.
"""

import hashlib
import re
from dataclasses import dataclass

_BYTE_RANGE = re.compile(rb"/ByteRange\s*\[\s*0\s+(\d{1,12})\s+(\d{1,12})\s+(\d{1,12})\s*\]")


class SignatureBytesError(ValueError):
    """O PDF preparado não tem a forma esperada (worker com defeito ou comprometido)."""


@dataclass(frozen=True)
class ReservedContents:
    start: int  # posição do "<" do /Contents
    end: int  # posição logo depois do ">"

    @property
    def capacity(self) -> int:
        """Quantos dígitos hex cabem entre "<" e ">"."""
        return self.end - self.start - 2


def reserved_contents(prepared_pdf: bytes, *, after: int = 0) -> ReservedContents:
    """Região do /Contents ainda vazia (`<000...0>`) da última assinatura, pelo /ByteRange.

    `after`: o /ByteRange e o /Contents têm que estar depois dessa posição (o fim do
    original), para que o worker não "reaproveite" uma assinatura que já estava no PDF.
    """
    matches = list(_BYTE_RANGE.finditer(prepared_pdf, after))
    if not matches:
        raise SignatureBytesError("sem /ByteRange na parte acrescentada")
    start, end, rest = (int(v) for v in matches[-1].groups())
    if not (after < start < end and end + rest == len(prepared_pdf)):
        raise SignatureBytesError("/ByteRange não cobre o arquivo inteiro")
    region = prepared_pdf[start:end]
    if len(region) < 3 or region[:1] != b"<" or region[-1:] != b">" or region[1:-1].strip(b"0"):
        raise SignatureBytesError("/Contents reservado não está vazio")
    return ReservedContents(start=start, end=end)


def check_prepared(original_pdf: bytes, prepared_pdf: bytes) -> tuple[ReservedContents, bytes]:
    """Confere o PDF preparado e devolve a região reservada e o digest calculado AQUI."""
    if len(prepared_pdf) <= len(original_pdf) or not prepared_pdf.startswith(original_pdf):
        raise SignatureBytesError("o preparado não começa com o original")
    region = reserved_contents(prepared_pdf, after=len(original_pdf))
    digest = hashlib.sha256()
    digest.update(memoryview(prepared_pdf)[: region.start])
    digest.update(memoryview(prepared_pdf)[region.end :])
    return region, digest.digest()


def embed_cms(prepared_pdf: bytes, region: ReservedContents, cms_der: bytes) -> bytes:
    """PDF assinado: o preparado com o CMS (hex, completado com zeros) dentro do /Contents."""
    hex_cms = cms_der.hex().encode("ascii")
    if not cms_der or cms_der[:1] != b"\x30" or len(hex_cms) > region.capacity:
        raise SignatureBytesError("CMS vazio, fora do formato ou maior que o espaço reservado")
    signed = bytearray(prepared_pdf)
    signed[region.start + 1 : region.end - 1] = hex_cms + b"0" * (region.capacity - len(hex_cms))
    return bytes(signed)
