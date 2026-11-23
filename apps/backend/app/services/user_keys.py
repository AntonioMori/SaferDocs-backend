"""Chaves de assinatura por usuário (REQ-45).

Chamada no cadastro, depois de o usuário ser criado:

    generate_user_keys(db, user)

Preenche `user.signing_public_key`, `user.signing_cert` (X.509 autoassinado
com o nome do usuário) e `user.signing_private_key_enc` (cifrada com
`aead.encrypt(AeadContext.SIGNING_KEY, ..., associated_data=user.id.bytes)`).
Não faz commit: quem chama controla a transação.

STUB (INFRA-02) | implementação real: REQ-45 (dono: v1ct0rjoao).
Hoje não faz nada, com a mesma assinatura.
"""

from sqlalchemy.orm import Session

from app.db.models import User


def generate_user_keys(db: Session, user: User) -> None:
    """Gera e associa ao usuário o par de chaves de assinatura."""
    del db, user  # usados pela implementação real
