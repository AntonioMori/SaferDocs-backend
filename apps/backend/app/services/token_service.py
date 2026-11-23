"""Emissão de tokens ao final de qualquer login.

`issue_tokens` é chamada pelo login com senha, pelo passo do TOTP e pelo
login com passkey. Ela cria uma sessão (REQ-28), emite o access token com o
claim `session_id` e um refresh token opaco (REQ-19), entregue apenas no
cookie HttpOnly (REQ-20). Não faz commit: quem chama controla a transação.
"""

import hashlib
import ipaddress
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from fastapi import Request, Response
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.request_info import client_ip, user_agent
from app.crypto.jwt import encode_access_token
from app.crypto.keyed_hash import keyed_hash
from app.db.models import RefreshToken, User, UserSession

REFRESH_TOKEN_BYTES = 32  # 256 bits (REQ-19)
REFRESH_COOKIE_NAME = "saferdocs_refresh"
REFRESH_COOKIE_PATH = "/api/v1/auth"  # o navegador só envia o cookie às rotas de autenticação


@dataclass(frozen=True)
class IssuedTokens:
    access_token: str
    expires_in: int
    token_type: str = "Bearer"
    # Nunca vai no corpo da resposta: só no cookie HttpOnly (REQ-20).
    refresh_token: str = field(default="", repr=False)


def hash_refresh_token(token: str) -> str:
    """SHA-256 do refresh token. Basta um hash rápido: o valor tem 256 bits aleatórios."""
    return hashlib.sha256(token.encode()).hexdigest()


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
    token, _ = encode_access_token(user.id, {"session_id": str(session.id), "ua_hash": session.ua_hmac})
    return token


def create_refresh_token(db: Session, session: UserSession) -> str:
    """Sorteia um refresh token opaco (CSPRNG) e guarda apenas o hash, com validade de 7 dias."""
    token = secrets.token_urlsafe(REFRESH_TOKEN_BYTES)
    db.add(
        RefreshToken(
            session_id=session.id,
            token_sha256=hash_refresh_token(token),
            expires_at=datetime.now(UTC) + timedelta(seconds=get_settings().refresh_token_ttl_seconds),
        )
    )
    db.flush()
    return token


def set_refresh_cookie(response: Response, token: str) -> None:
    """REQ-20: HttpOnly (JS não lê), Secure (só HTTPS), SameSite=Strict (não vai em requisição
    de outro site) e Path restrito às rotas de autenticação."""
    settings = get_settings()
    response.set_cookie(
        key=REFRESH_COOKIE_NAME,
        value=token,
        max_age=settings.refresh_token_ttl_seconds,
        path=REFRESH_COOKIE_PATH,
        secure=settings.cookie_secure,
        httponly=True,
        samesite="strict",
    )


def clear_refresh_cookie(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(
        key=REFRESH_COOKIE_NAME,
        path=REFRESH_COOKIE_PATH,
        secure=settings.cookie_secure,
        httponly=True,
        samesite="strict",
    )


def issue_tokens(db: Session, user: User, request: Request, response: Response) -> IssuedTokens:
    """Cria a sessão, emite o access token e coloca o refresh token no cookie de `response`."""
    session = create_session(db, user, request)
    refresh = create_refresh_token(db, session)
    set_refresh_cookie(response, refresh)
    return IssuedTokens(
        access_token=access_token_for(user, session),
        expires_in=get_settings().access_token_ttl_seconds,
        refresh_token=refresh,
    )


def _valid_inet(ip: str | None) -> str | None:
    """Só guarda na coluna INET o que for um endereço IP de verdade."""
    if not ip:
        return None
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return None
