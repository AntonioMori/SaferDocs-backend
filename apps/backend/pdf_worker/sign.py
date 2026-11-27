"""Assinatura do PDF no worker (REQ-46), em duas operações, sem a chave privada.

    prepare_sign: PDF + página/posição + linhas do selo + certificado do assinante
                  -> PDF com o campo de assinatura, o selo desenhado e o /Contents
                     reservado, e o SHA-256 dos bytes cobertos pelo /ByteRange.
    (a API confere o preparado, recalcula o digest, monta o CMS com a chave do
    usuário e o escreve no /Contents: app/pdf/signature_bytes.py)

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

from asn1crypto import pem, x509
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import fields, signers
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.sign.validation.status import SignatureCoverageLevel
from pyhanko_certvalidator import ValidationContext

from pdf_worker import seal
from pdf_worker.ops import OpError, page_sizes
from pdf_worker.protocol import (
    ERR_ALREADY_SIGNED,
    ERR_BAD_REQUEST,
    ERR_HAS_JAVASCRIPT,
    ERR_INVALID_POSITION,
    ERR_UNPROCESSABLE,
    SEAL_HEIGHT,
    SEAL_WIDTH,
)

# Espaço reservado para o CMS (hex): sobra para P-256 + certificado + atributos.
CONTENTS_RESERVED_BYTES = 8192
FIELD_PREFIX = "SaferDocs"

# Nome do campo que o SaferDocs cria: "SaferDocs-" + 32 hexadecimais (uuid4().hex).
_OUR_FIELD = re.compile(rf"{FIELD_PREFIX}-[0-9a-f]{{32}}")


def _already_signed_by_us(pdf: bytes) -> bool:
    """O PDF já tem uma assinatura do SaferDocs (campo com o nosso prefixo).

    Assinar de novo o arquivo que o SaferDocs devolveu criaria uma segunda assinatura sobre a
    primeira: o documento é o mesmo, então a segunda é recusada. Assinaturas de outros sistemas
    não impedem: o SaferDocs pode assinar um PDF que já veio assinado de fora.
    """
    try:
        signatures = PdfFileReader(io.BytesIO(pdf), strict=False).embedded_signatures
    except Exception:  # noqa: BLE001 - se nem abre, a assinatura vai recusar como não processável
        return False
    return any(_OUR_FIELD.fullmatch(sig.field_name or "") for sig in signatures)


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
    """Writer incremental do pyHanko: a assinatura é ACRESCENTADA, o original fica intacto.

    O leitor é tolerante (`strict=False`): PDF de outros sistemas (a Docusign, por
    exemplo) costuma ter defeitos pequenos na xref, como a geração da entrada 0 fora
    do padrão, que todo leitor de PDF aceita. O writer só ACRESCENTA, nunca regrava o
    original, e a API ainda confere que o PDF assinado começa com o arquivo exato que
    o usuário mandou. O que nem assim abre continua sendo não processável.
    """
    try:
        return IncrementalPdfFileWriter(io.BytesIO(pdf), strict=False)
    except Exception:  # noqa: BLE001 - qualquer recusa do leitor estrito: não processável
        raise OpError(ERR_UNPROCESSABLE) from None


def prepare_sign(pdf: bytes, args: dict[str, Any]) -> tuple[dict[str, Any], bytes]:
    page = args.get("page")
    if isinstance(page, bool) or not isinstance(page, int):
        raise OpError(ERR_BAD_REQUEST)
    x, y = _number(args.get("x")), _number(args.get("y"))
    seal_lines = seal.clean_lines(args.get("seal_lines"))
    cert = _certificate(args.get("signer_cert_pem"))

    # Mesmas checagens de todo PDF (JavaScript, objetos perdidos, MediaBox) e a posição.
    pages = page_sizes(pdf)
    if not 1 <= page <= len(pages):
        raise OpError(ERR_INVALID_POSITION)
    size = pages[page - 1]
    if not (0 <= x and 0 <= y and x + SEAL_WIDTH <= size["width"] and y + SEAL_HEIGHT <= size["height"]):
        raise OpError(ERR_INVALID_POSITION)
    if _already_signed_by_us(pdf):
        raise OpError(ERR_ALREADY_SIGNED)

    async def digest() -> tuple[Any, bytes]:
        signer = signers.ExternalSigner(signing_cert=cert, cert_registry=None, signature_value=bytes(72))
        field_name = f"{FIELD_PREFIX}-{uuid.uuid4().hex}"  # único: o PDF pode ter outras assinaturas
        meta = signers.PdfSignatureMetadata(field_name=field_name, md_algorithm="sha256")
        style = seal.stamp_style(seal_lines)
        # (x, y) é relativo ao canto inferior esquerdo da página, mesmo que o MediaBox não comece em 0.
        left, bottom = x + size["left"], y + size["bottom"]
        box = (left, bottom, left + SEAL_WIDTH, bottom + SEAL_HEIGHT)
        spec = fields.SigFieldSpec(field_name, on_page=page - 1, box=box)
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


_ALTERED_ERRORS = (ERR_UNPROCESSABLE, ERR_HAS_JAVASCRIPT)


# Marcas do dicionário de uma assinatura PDF: /ByteRange, o SubFilter do CMS, o /Type /Sig e um
# /Contents com hexadecimal longo (o CMS). O pyHanko escreve /Contents antes dos outros, então um
# arquivo cortado no meio do CMS só tem esta última marca.
_SIGNED_MARKS = re.compile(
    rb"/ByteRange|/adbe\.pkcs7\.detached|/Type\s*/Sig(?![A-Za-z0-9])|/Contents\s*<[0-9A-Fa-f]{64}"
)


def _looks_signed(pdf: bytes) -> bool:
    """O arquivo tem o dicionário de uma assinatura PDF, mesmo que não dê mais para lê-lo."""
    return _SIGNED_MARKS.search(pdf) is not None


def verify(pdf: bytes, args: dict[str, Any]) -> tuple[dict[str, Any], bytes]:
    """Confere a assinatura embutida mais recente (REQ-50): CMS, integridade e cobertura.

    Não regrava nada: a assinatura vale para os bytes exatos do arquivo recebido.
    A confiança no certificado não vem de uma autoridade (é autoassinado): a API
    compara a chave pública dele com a registrada para o usuário (REQ-51).
    """
    del args
    result: dict[str, Any] = {
        "has_signature": False,
        "cms_valid": False,
        "covers_whole_file": False,
        "signer_public_key_der": None,
        "signature_count": 0,
    }
    try:
        page_sizes(pdf)  # recusa JavaScript e PDF que não abre, como em toda operação
        reader = PdfFileReader(io.BytesIO(pdf), strict=False)
        signatures = list(reader.embedded_signatures)
    except Exception as exc:  # noqa: BLE001 - estrutura que não dá para ler nem verificar
        # Um PDF assinado pelo SaferDocs abre e não tem JavaScript (a assinatura recusa os
        # dois). Se ele tem cara de assinado e não passa mais, foi alterado depois: é
        # adulterado, não "PDF inválido" (REQ-52).
        if _looks_signed(pdf) and (not isinstance(exc, OpError) or exc.code in _ALTERED_ERRORS):
            result.update(has_signature=True, signature_count=1)
            return result, b""
        if isinstance(exc, OpError):
            raise
        raise OpError(ERR_UNPROCESSABLE) from None
    # Dicionário de assinatura que o pyHanko ignora (SubFilter desconhecido etc.): há assinatura
    # que não dá para validar, então é adulterado, não "não encontrada".
    has_signature = bool(signatures) or _looks_signed(pdf)
    result.update(has_signature=has_signature, signature_count=len(signatures) or int(has_signature))
    if not signatures:
        return result, b""
    latest = max(signatures, key=lambda s: s.signed_revision)
    try:
        cert = latest.signer_cert
        context = ValidationContext(trust_roots=[cert], allow_fetching=False)
        status = validate_pdf_signature(latest, signer_validation_context=context)
        result["cms_valid"] = bool(status.intact and status.valid)
        result["covers_whole_file"] = status.coverage == SignatureCoverageLevel.ENTIRE_FILE
        result["signer_public_key_der"] = base64.b64encode(cert.public_key.dump()).decode("ascii")
    except Exception:  # noqa: BLE001 - CMS quebrado ou forjado: assinatura presente mas inválida
        result["cms_valid"] = False
    return result, b""
