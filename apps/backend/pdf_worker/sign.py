"""Assinatura do PDF no worker (REQ-46), em duas operações, sem a chave privada.

    prepare_sign: PDF + página/posição + texto do selo + certificado do assinante
                  -> PDF com o campo de assinatura, o selo desenhado e o /Contents
                     reservado, e o SHA-256 dos bytes cobertos pelo /ByteRange.
    (a API monta o CMS sobre esse digest com a chave do usuário)
    finish_sign:  PDF preparado + CMS -> PDF assinado (o CMS é escrito no /Contents).

É a assinatura em etapas do pyHanko ("interrupted signing"), padrão PDF
Signature da ISO 32000: a assinatura vai dentro do arquivo, num campo de
assinatura com aparência (o selo), e cobre o arquivo inteiro por /ByteRange.
"""

import asyncio
import base64
import binascii
import io
import math
import re
import uuid
from typing import Any

import pikepdf
from asn1crypto import pem, x509
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields, signers
from pyhanko.stamp import TextStampStyle

from pdf_worker.ops import OpError, page_sizes
from pdf_worker.protocol import (
    ERR_BAD_REQUEST,
    ERR_INVALID_POSITION,
    ERR_UNPROCESSABLE,
    MAX_SEAL_LINE_LENGTH,
    MAX_SEAL_LINES,
    SEAL_HEIGHT,
    SEAL_WIDTH,
)

# Espaço reservado para o CMS (hex): sobra para P-256 + certificado + atributos.
CONTENTS_RESERVED_BYTES = 8192
FIELD_PREFIX = "SaferDocs"
_BYTE_RANGE = re.compile(rb"/ByteRange\s*\[\s*0\s+(\d+)\s+(\d+)\s+(\d+)\s*\]")


def _seal_text(lines: Any) -> str:
    if not isinstance(lines, list) or not 1 <= len(lines) <= MAX_SEAL_LINES:
        raise OpError(ERR_BAD_REQUEST)
    clean = []
    for line in lines:
        if not isinstance(line, str) or len(line) > MAX_SEAL_LINE_LENGTH:
            raise OpError(ERR_BAD_REQUEST)
        # A fonte padrão do selo é WinAnsi: o que não cabe vira "?". O pyHanko formata o
        # texto com "%" (%(signer)s...), então "%" do usuário precisa ser escapado.
        text = "".join(c if c.isprintable() else " " for c in line)
        clean.append(text.encode("cp1252", errors="replace").decode("cp1252").replace("%", "%%"))
    return "\n".join(clean)


def _number(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(value):
        raise OpError(ERR_BAD_REQUEST)
    return float(value)


def _certificate(value: Any) -> x509.Certificate:
    if not isinstance(value, str):
        raise OpError(ERR_BAD_REQUEST)
    try:
        data = value.encode("ascii")
        if pem.detect(data):
            _, _, data = pem.unarmor(data)
        else:
            data = base64.b64decode(data, validate=True)
        cert = x509.Certificate.load(data)
        cert.public_key  # noqa: B018 - força o parse agora, não no meio da assinatura
        return cert
    except (ValueError, TypeError, binascii.Error):
        raise OpError(ERR_BAD_REQUEST) from None


def _incremental_writer(pdf: bytes) -> IncrementalPdfFileWriter:
    """Writer incremental do pyHanko; se o leitor estrito dele recusar o arquivo, usa a versão do qpdf.

    O qpdf reconstrói xref ausente ou quebrada (o PDF já passou por ele na recusa de
    JavaScript); o pyHanko não. Regravar pelo qpdf mantém o conteúdo e dá um arquivo
    bem formado para a assinatura incremental.
    """
    try:
        return IncrementalPdfFileWriter(io.BytesIO(pdf))
    except Exception:  # noqa: BLE001 - qualquer recusa do leitor estrito cai na versão regravada
        with pikepdf.open(io.BytesIO(pdf)) as document:
            # O qpdf só escreve /Size (obrigatório para o pyHanko) se a chave já existir no
            # trailer; o valor é recalculado na gravação.
            document.trailer.Size = 0
            rewritten = io.BytesIO()
            document.save(rewritten)
        return IncrementalPdfFileWriter(io.BytesIO(rewritten.getvalue()))


def prepare_sign(pdf: bytes, args: dict[str, Any]) -> tuple[dict[str, Any], bytes]:
    page = args.get("page")
    if isinstance(page, bool) or not isinstance(page, int):
        raise OpError(ERR_BAD_REQUEST)
    x, y = _number(args.get("x")), _number(args.get("y"))
    stamp_text = _seal_text(args.get("seal_lines"))
    cert = _certificate(args.get("signer_cert_pem"))

    # Mesmas checagens de todo PDF (JavaScript, objetos perdidos, MediaBox) e a posição.
    pages = page_sizes(pdf)
    if not 1 <= page <= len(pages):
        raise OpError(ERR_INVALID_POSITION)
    size = pages[page - 1]
    if not (0 <= x and 0 <= y and x + SEAL_WIDTH <= size["width"] and y + SEAL_HEIGHT <= size["height"]):
        raise OpError(ERR_INVALID_POSITION)

    async def digest() -> tuple[Any, bytes]:
        signer = signers.ExternalSigner(signing_cert=cert, cert_registry=None, signature_value=bytes(72))
        field_name = f"{FIELD_PREFIX}-{uuid.uuid4().hex}"  # único: o PDF pode ter outras assinaturas
        meta = signers.PdfSignatureMetadata(field_name=field_name, md_algorithm="sha256")
        style = TextStampStyle(stamp_text=stamp_text)
        spec = fields.SigFieldSpec(field_name, on_page=page - 1, box=(x, y, x + SEAL_WIDTH, y + SEAL_HEIGHT))
        pdf_signer = signers.PdfSigner(meta, signer=signer, stamp_style=style, new_field_spec=spec)
        writer = _incremental_writer(pdf)
        prepared, _, output = await pdf_signer.async_digest_doc_for_signing(
            writer, bytes_reserved=CONTENTS_RESERVED_BYTES
        )
        return prepared, output.getvalue()

    try:
        prepared, prepared_pdf = asyncio.run(digest())
    except OpError:
        raise
    except Exception:  # noqa: BLE001 - erro do pyHanko com o PDF: não processável, sem detalhes
        raise OpError(ERR_UNPROCESSABLE) from None
    return {"digest": prepared.document_digest.hex()}, prepared_pdf


def _reserved_region(prepared_pdf: bytes) -> tuple[int, int]:
    """Região do /Contents ainda vazia (`<000...0>`) da última assinatura, pelo /ByteRange."""
    matches = list(_BYTE_RANGE.finditer(prepared_pdf))
    if not matches:
        raise OpError(ERR_BAD_REQUEST)
    start, end, rest = (int(v) for v in matches[-1].groups())
    if not (0 < start < end <= len(prepared_pdf) and end + rest == len(prepared_pdf)):
        raise OpError(ERR_BAD_REQUEST)
    region = prepared_pdf[start:end]
    if region[:1] != b"<" or region[-1:] != b">" or region[1:-1].strip(b"0"):
        raise OpError(ERR_BAD_REQUEST)  # não é um PDF preparado por prepare_sign
    return start, end


def finish_sign(pdf: bytes, args: dict[str, Any]) -> tuple[dict[str, Any], bytes]:
    """Escreve o CMS (DER, base64 em args["cms"]) no /Contents reservado do PDF preparado."""
    raw_cms = args.get("cms")
    if not isinstance(raw_cms, str):
        raise OpError(ERR_BAD_REQUEST)
    try:
        cms_der = base64.b64decode(raw_cms, validate=True)
    except (ValueError, binascii.Error):
        raise OpError(ERR_BAD_REQUEST) from None
    start, end = _reserved_region(pdf)
    hex_cms = cms_der.hex().encode("ascii")
    capacity = end - start - 2
    if not cms_der or cms_der[:1] != b"\x30" or len(hex_cms) > capacity:
        raise OpError(ERR_BAD_REQUEST)
    signed = bytearray(pdf)
    signed[start + 1 : end - 1] = hex_cms + b"0" * (capacity - len(hex_cms))
    return {}, bytes(signed)
