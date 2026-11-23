"""Dependências compartilhadas pelas rotas.

`get_current_user` é a porta de entrada de toda rota autenticada. Rotas
protegidas devem usá-la no router inteiro, não rota a rota:

    router = APIRouter(dependencies=[Depends(get_current_user)])

Verificações feitas hoje: assinatura, emissor e expiração do JWT; sessão
existente, do mesmo usuário e não revogada (REQ-28).
Ainda falta (REQ-22, mesma assinatura): denylist, troca de senha,
User-Agent e alerta de IP (Figura 4).
Para testar rotas protegidas: `uv run python scripts/dev_token.py`.
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated

import jwt
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.errors import AppError, ErrorCode
from app.crypto.jwt import decode_access_token
from app.db.models import User, UserSession
from app.db.session import get_db

_bearer = HTTPBearer(auto_error=False)
LAST_SEEN_RESOLUTION = timedelta(minutes=1)

DbSession = Annotated[Session, Depends(get_db)]


@dataclass(frozen=True)
class AuthContext:
    """Quem está autenticado e em qual sessão (útil para logout e sessões ativas)."""

    user: User
    session: UserSession
    claims: dict


def get_auth_context(
    request: Request,
    db: DbSession,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> AuthContext:
    if credentials is None:
        raise AppError(ErrorCode.AUTH_TOKEN_INVALID)
    try:
        claims = decode_access_token(credentials.credentials)
        user_id = uuid.UUID(claims["sub"])
        session_id = uuid.UUID(claims["session_id"])
    except (jwt.PyJWTError, ValueError):
        raise AppError(ErrorCode.AUTH_TOKEN_INVALID) from None

    # REQ-28: a sessão precisa existir, ser do mesmo usuário e não ter sido revogada.
    session = db.get(UserSession, session_id)
    if session is None or session.user_id != user_id or session.revoked_at is not None:
        raise AppError(ErrorCode.AUTH_TOKEN_REVOKED)

    user = db.get(User, user_id)
    if user is None:
        raise AppError(ErrorCode.AUTH_TOKEN_INVALID)

    now = datetime.now(UTC)
    if now - session.last_seen_at > LAST_SEEN_RESOLUTION:
        session.last_seen_at = now
        db.commit()

    request.state.token_claims = claims
    return AuthContext(user=user, session=session, claims=claims)


def get_current_user(context: Annotated[AuthContext, Depends(get_auth_context)]) -> User:
    """Usuário dono do access token (ErrorCode.AUTH_TOKEN_INVALID / AUTH_TOKEN_REVOKED se não)."""
    return context.user


CurrentUser = Annotated[User, Depends(get_current_user)]
CurrentAuth = Annotated[AuthContext, Depends(get_auth_context)]
