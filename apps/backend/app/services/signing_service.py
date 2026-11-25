"""Assinatura de PDF (REQ-46 a 49), no caminho da Figura 7 do enunciado.

    valida o PDF -> hash do original -> selo e assinatura -> hash do assinado
    -> registra no banco -> devolve e descarta

A chave privada nunca sai da API (REQ-59): o worker prepara o PDF e devolve o
digest; a API monta o CMS com a chave do usuário; o worker só escreve o CMS
no arquivo. O PDF nunca é guardado: só os hashes e os metadados.
"""

import datetime as dt
import hashlib
import math
import uuid
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fastapi import Request
from sqlalchemy.orm import Session

from app.core.errors import AppError, ErrorCode, FieldError
from app.crypto.cms import build_signed_data
from app.db.models import User
from app.pdf import client as pdf_client
from app.pdf.upload import PdfUpload
from app.services.user_keys import generate_user_keys, sign_with_user_key

MAX_PAGE = 100_000
MAX_COORDINATE = 14_400  # maior página que o PDF permite
MAX_SEAL_NAME = 34  # "Assinado por: " + nome cabe numa linha do selo


@dataclass(frozen=True)
class SignedDocument:
    pdf: bytes
    signature_id: uuid.UUID


@dataclass(frozen=True)
class SealPosition:
    page: int
    x: float
    y: float


def parse_position(fields: dict[str, str]) -> SealPosition:
    """Página (a partir de 1) e canto inferior esquerdo do selo, em pontos PDF."""
    errors: list[FieldError] = []
    page = 0
    try:
        page = int(fields["page"])
        if not 1 <= page <= MAX_PAGE:
            errors.append(FieldError("page", "deve ser >= 1"))
    except ValueError:
        errors.append(FieldError("page", "deve ser um número inteiro"))
    coords: dict[str, float] = {}
    for name in ("x", "y"):
        try:
            value = float(fields[name])
            if not math.isfinite(value) or not 0 <= value <= MAX_COORDINATE:
                raise ValueError
            coords[name] = round(value, 2)
        except ValueError:
            errors.append(FieldError(name, "deve ser um número entre 0 e 14400"))
    if errors:
        raise AppError(ErrorCode.VALIDATION, fields=errors)
    return SealPosition(page=page, x=coords["x"], y=coords["y"])


def seal_lines(
    user: User, signature_id: uuid.UUID, signed_at: dt.datetime, original_sha256: str
) -> list[str]:
    """Texto do selo visual (REQ-47): quem, quando (UTC), hash do original e id da assinatura.

    O selo tem 240 pt de largura: cada linha cabe em ~45 caracteres. O SHA-256
    vai inteiro, em duas linhas, para poder ser conferido sem outra ferramenta.
    """
    name = " ".join((user.name or "").split())  # sem quebras de linha nem espaços repetidos
    if len(name) > MAX_SEAL_NAME:
        name = name[: MAX_SEAL_NAME - 3] + "..."
    return [
        f"Assinado por: {name}",
        f"Em: {signed_at.astimezone(dt.UTC):%Y-%m-%d %H:%M:%S} UTC",
        f"SHA-256: {original_sha256[:32]}",
        f"         {original_sha256[32:]}",
        f"ID: {signature_id}",
    ]


def _signer_cert_pem(db: Session, user: User) -> bytes:
    if not user.signing_cert or not user.signing_private_key_enc:
        # Conta criada antes do REQ-45: gera o par agora, uma vez.
        generate_user_keys(db, user)
        db.commit()
    return x509.load_der_x509_certificate(user.signing_cert).public_bytes(serialization.Encoding.PEM)


def sign_document(db: Session, user: User, upload: PdfUpload, request: Request) -> SignedDocument:
    del request  # usado pelo registro (REQ-48)
    position = parse_position(upload.fields)
    signature_id = uuid.uuid4()
    signed_at = dt.datetime.now(dt.UTC).replace(microsecond=0)
    original_sha256 = hashlib.sha256(upload.pdf).hexdigest()
    cert_pem = _signer_cert_pem(db, user)

    prepared = pdf_client.prepare_sign(
        upload.pdf,
        page=position.page,
        x=position.x,
        y=position.y,
        seal_lines=seal_lines(user, signature_id, signed_at, original_sha256),
        signer_cert_pem=cert_pem,
    )
    cms_der = build_signed_data(
        document_digest=prepared.digest,
        signer_cert_der=user.signing_cert,
        signing_time=signed_at,
        sign=lambda data: sign_with_user_key(user, data),
    )
    signed_pdf = pdf_client.finish_sign(prepared.prepared_pdf, cms_der)
    return SignedDocument(pdf=signed_pdf, signature_id=signature_id)
