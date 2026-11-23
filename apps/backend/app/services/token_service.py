"""Emissão de tokens ao final de qualquer login.

`issue_tokens` é chamada pelo login com senha, pelo passo do TOTP, pelo
login com passkey e pelo refresh.

STUB (INFRA-02) | implementação real: REQ-18/19/20/28 (dono: AntonioMori).
Hoje só emite o access token. A versão real cria a sessão, o refresh token
opaco e o cookie HttpOnly, sem mudar a assinatura nem o retorno.
"""

from dataclasses import dataclass

from fastapi import Request, Response
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.crypto.jwt import encode_access_token
from app.db.models import User


@dataclass(frozen=True)
class IssuedTokens:
    access_token: str
    expires_in: int
    token_type: str = "Bearer"


def issue_tokens(db: Session, user: User, request: Request, response: Response) -> IssuedTokens:
    """Emite o par de tokens do usuário. O refresh vai só no cookie de `response`."""
    del db, request, response  # usados pela implementação real
    token, _ = encode_access_token(user.id)
    return IssuedTokens(access_token=token, expires_in=get_settings().access_token_ttl_seconds)
