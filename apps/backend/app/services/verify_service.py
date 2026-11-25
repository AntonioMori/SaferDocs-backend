"""Verificação de autenticidade de PDF (REQ-50 a 54), no caminho da Figura 8.

    há assinatura embutida?  não -> assinatura não encontrada
    a assinatura confere?    não -> documento adulterado   (CMS, integridade e cobertura, REQ-50)
    o hash bate com o registrado? não -> documento adulterado (REQ-51)
                                  sim -> documento íntegro

O PDF recebido é processado em memória e descartado: só o resultado vai
para a auditoria (REQ-54).
"""

import hashlib

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import AppError
from app.db.models import Signature, User
from app.pdf import client as pdf_client
from app.schemas.documents import VerificationOut, VerificationStatus
from app.services import audit_service as audit


def find_registered_signature(
    db: Session, signed_sha256: str, signer_public_key_der: bytes | None
) -> Signature | None:
    """Assinatura registrada com este hash do arquivo assinado e feita com esta chave (REQ-51).

    O hash sozinho não basta: o registro só vale se a chave pública do certificado
    embutido for a do usuário que assinou. Um PDF que alguém reassine com outra
    chave, mantendo os bytes de um documento registrado, não casa.
    """
    if not signer_public_key_der:
        return None
    rows = db.execute(
        select(Signature, User.signing_public_key)
        .join(User, User.id == Signature.user_id)
        .where(Signature.signed_sha256 == signed_sha256)
    ).all()
    for signature, public_key in rows:
        if public_key is not None and public_key == signer_public_key_der:
            return signature
    return None


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_document(db: Session, pdf: bytes, request: Request) -> VerificationOut:
    """Os três resultados da Figura 8 (REQ-52). Toda verificação vai para a auditoria."""
    try:
        result = _verify(db, pdf)
    except AppError as error:
        _audit(db, request, audit.AuditResult.FAILURE, {"error": str(error.code)})
        raise
    details: dict[str, str] = {"status": result.status.value}
    if result.signature_id:
        details["signature_id"] = str(result.signature_id)
    _audit(db, request, audit.AuditResult.SUCCESS, details)
    return result


def _verify(db: Session, pdf: bytes) -> VerificationOut:
    embedded = pdf_client.verify(pdf)
    if not embedded.has_signature:
        return VerificationOut(status=VerificationStatus.NAO_ENCONTRADA)
    if not (embedded.cms_valid and embedded.covers_whole_file):
        return VerificationOut(status=VerificationStatus.ADULTERADO)
    registered = find_registered_signature(db, sha256_hex(pdf), embedded.signer_public_key_der)
    if registered is None:
        return VerificationOut(status=VerificationStatus.ADULTERADO)
    signer = db.get(User, registered.user_id)
    return VerificationOut(
        status=VerificationStatus.INTEGRO,
        signer_name=signer.name if signer else None,
        signed_at=registered.signed_at,
        signature_id=registered.id,
    )


def _audit(db: Session, request: Request, result: audit.AuditResult, details: dict[str, str]) -> None:
    audit.record(
        db, action=audit.AuditAction.DOCUMENT_VERIFIED, result=result, request=request, details=details
    )
    db.commit()
