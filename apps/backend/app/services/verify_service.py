"""Verificação de autenticidade de PDF (REQ-50 a 54), no caminho da Figura 8.

    há assinatura embutida?  não -> assinatura não encontrada
    a assinatura confere?    não -> documento adulterado   (CMS, integridade e cobertura, REQ-50)
    o hash bate com o registrado? não -> documento adulterado (REQ-51)
                                  sim -> documento íntegro

Várias pessoas podem assinar o mesmo arquivo, uma por cima da outra: cada assinatura do
SaferDocs cobre a revisão dela, e a última cobre o arquivo inteiro. Cada uma é conferida como
acima, com o hash do trecho que ela cobre (o arquivo que aquele assinante recebeu), e a cadeia
tem de fechar: quem assinou depois partiu exatamente do arquivo que o anterior recebeu. Qualquer
revisão no meio que não seja uma assinatura registrada do SaferDocs deixa o documento adulterado.

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
from app.schemas.documents import SignerOut, VerificationOut, VerificationStatus
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


def _chain(signatures: tuple[pdf_client.EmbeddedSignature, ...]) -> list[pdf_client.EmbeddedSignature]:
    """As assinaturas a conferir: da primeira do SaferDocs até a última do arquivo.

    As de outros sistemas feitas antes da primeira do SaferDocs não entram (o SaferDocs assina
    PDF que já veio assinado de fora). Sem nenhuma do SaferDocs, confere só a última, como antes.
    """
    first = next((i for i, sig in enumerate(signatures) if sig.ours), None)
    if first is None:
        return list(signatures[-1:])
    return list(signatures[first:])


def _verify(db: Session, pdf: bytes) -> VerificationOut:
    embedded = pdf_client.verify(pdf)
    if not embedded.has_signature:
        return VerificationOut(status=VerificationStatus.NAO_ENCONTRADA)
    if not (embedded.cms_valid and embedded.covers_whole_file):
        return VerificationOut(status=VerificationStatus.ADULTERADO)

    chain = _chain(embedded.signatures)
    if not chain:  # o worker não descreveu as assinaturas: confere a última pelo arquivo todo
        registered = find_registered_signature(db, sha256_hex(pdf), embedded.signer_public_key_der)
        records = [registered] if registered else []
    else:
        records = _registered_chain(db, pdf, chain)
    if not records:
        return VerificationOut(status=VerificationStatus.ADULTERADO)

    signers = []
    for record in records:
        user = db.get(User, record.user_id)
        signers.append(
            SignerOut(
                signer_name=user.name if user else None, signed_at=record.signed_at, signature_id=record.id
            )
        )
    last = signers[-1]
    return VerificationOut(
        status=VerificationStatus.INTEGRO,
        signer_name=last.signer_name,
        signed_at=last.signed_at,
        signature_id=last.signature_id,
        signers=signers,
    )


def _registered_chain(db: Session, pdf: bytes, chain: list[pdf_client.EmbeddedSignature]) -> list[Signature]:
    """O registro de cada assinatura da cadeia, ou lista vazia se alguma não confere (adulterado)."""
    records: list[Signature] = []
    previous_sha256: str | None = None
    for index, sig in enumerate(chain):
        last = index == len(chain) - 1
        covered = sig.covers_whole_file if last else sig.covers_revision
        if not (sig.cms_valid and covered) or (not last and sig.revision_end is None):
            return []
        revision = pdf if last else pdf[: sig.revision_end]
        revision_sha256 = sha256_hex(revision)
        registered = find_registered_signature(db, revision_sha256, sig.signer_public_key_der)
        if registered is None:
            return []
        # Quem assinou depois partiu do arquivo exato que o anterior recebeu: nada entrou no meio.
        if previous_sha256 is not None and registered.original_sha256 != previous_sha256:
            return []
        records.append(registered)
        previous_sha256 = revision_sha256
    return records


def _audit(db: Session, request: Request, result: audit.AuditResult, details: dict[str, str]) -> None:
    audit.record(
        db, action=audit.AuditAction.DOCUMENT_VERIFIED, result=result, request=request, details=details
    )
    db.commit()
