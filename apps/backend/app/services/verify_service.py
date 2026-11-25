"""Verificação de autenticidade de PDF (REQ-50 a 54), no caminho da Figura 8.

    há assinatura embutida?  não -> assinatura não encontrada
    a assinatura confere?    não -> documento adulterado   (CMS, integridade e cobertura, REQ-50)
    o hash bate com o registrado? não -> documento adulterado (REQ-51)
                                  sim -> documento íntegro

O PDF recebido é processado em memória e descartado: só o resultado vai
para a auditoria (REQ-54).
"""

import hashlib

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Signature, User


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
