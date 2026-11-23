"""Emissão de tokens ao final de qualquer login.

`issue_tokens` é chamada pelo login com senha, pelo passo do TOTP e pelo
login com passkey. Ela cria uma sessão (REQ-28) e emite o access token com
o claim `session_id`. Não faz commit: quem chama controla a transação.

Ainda falta (próximas issues, mesma assinatura): refresh token opaco e
cookie HttpOnly (REQ-19/20).
"""

import ipaddress
from dataclasses import dataclass

from fastapi import Request, Response
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.request_info import client_ip, user_agent
from app.crypto.jwt import encode_access_token
from app.crypto.keyed_hash import keyed_hash
from app.db.models import User, UserSession


@dataclass(frozen=True)
class IssuedTokens:
    access_token: str
    expires_in: int
    token_type: str = "Bearer"


def create_session(db: Session, user: User, request: Request) -> UserSession:
    """Nova sessão com a origem do login (IP e User-Agent também como HMAC)."""
    ip = client_ip(request)
    ua = user_agent(request)
    session = UserSession(
        user_id=user.id,
        ip=_valid_inet(ip),
        user_agent=ua,
        ip_hmac=keyed_hash(ip or ""),
        ua_hmac=keyed_hash(ua),
    )
    db.add(session)
    db.flush()
    return session


def access_token_for(user: User, session: UserSession) -> str:
    token, _ = encode_access_token(user.id, {"session_id": str(session.id)})
    return token


def issue_tokens(db: Session, user: User, request: Request, response: Response) -> IssuedTokens:
    """Cria a sessão e emite o par de tokens do usuário."""
    del response  # recebe o cookie do refresh token (REQ-20)
    session = create_session(db, user, request)
    return IssuedTokens(
        access_token=access_token_for(user, session),
        expires_in=get_settings().access_token_ttl_seconds,
    )


def _valid_inet(ip: str | None) -> str | None:
    """Só guarda na coluna INET o que for um endereço IP de verdade."""
    if not ip:
        return None
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return None
