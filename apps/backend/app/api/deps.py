"""Dependências compartilhadas pelas rotas.

`get_current_user` é a porta de entrada de toda rota autenticada. Rotas
protegidas devem usá-la no router inteiro, não rota a rota:

    router = APIRouter(dependencies=[Depends(get_current_user)])

A cadeia segue a Figura 4 do enunciado, nesta ordem:
  1. assinatura e validade do JWT (REQ-17/18)    -> AUTH_TOKEN_INVALID
  2. jti na denylist (REQ-21/22)                 -> AUTH_TOKEN_REVOKED
  3. emitido antes da troca de senha (REQ-25)    -> AUTH_TOKEN_REVOKED
  4. User-Agent diferente do login (REQ-27)      -> AUTH_TOKEN_REVOKED
  5. sessão inexistente ou revogada (REQ-28)     -> AUTH_TOKEN_REVOKED
  6. IP diferente do login: só alerta (REQ-26)

Rotas que não exigem autenticação precisam estar em PUBLIC_ROUTES; um teste
garante que todas as outras passam por esta cadeia.
Para testar rotas protegidas: `uv run python scripts/dev_token.py`.
"""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated

import jwt
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import AppError, ErrorCode
from app.core.request_info import user_agent
from app.crypto.jwt import decode_access_token
from app.crypto.keyed_hash import keyed_hash_matches
from app.db.models import JwtDenylist, User, UserSession
from app.db.session import get_db
from app.services.session_alerts import check_ip

_bearer = HTTPBearer(auto_error=False)
LAST_SEEN_RESOLUTION = timedelta(minutes=1)

# Rotas acessíveis sem access token (método, caminho). Todas as demais exigem.
PUBLIC_ROUTES: frozenset[tuple[str, str]] = frozenset(
    {
        ("GET", "/api/v1/health"),
        ("POST", "/api/v1/auth/register"),
        ("POST", "/api/v1/auth/login"),
        ("POST", "/api/v1/auth/login/totp"),  # REQ-15: autenticado pelo mfa_token
        ("POST", "/api/v1/auth/refresh"),  # REQ-29: autenticado pelo cookie de refresh
        ("POST", "/api/v1/auth/passkeys/login/options"),  # REQ-06
        ("POST", "/api/v1/auth/passkeys/login/verify"),  # REQ-06
        ("POST", "/api/v1/verify"),  # REQ-52: verificação pública
    }
)

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
    # 1. Assinatura, algoritmo, emissor, expiração e claims obrigatórios.
    if credentials is None:
        raise AppError(ErrorCode.AUTH_TOKEN_INVALID)
    try:
        claims = decode_access_token(credentials.credentials)
        user_id = uuid.UUID(claims["sub"])
        session_id = uuid.UUID(claims["session_id"])
    except (jwt.PyJWTError, ValueError):
        raise AppError(ErrorCode.AUTH_TOKEN_INVALID) from None

    # 2. REQ-22: token revogado no logout, mesmo que ainda criptograficamente válido.
    if db.scalar(select(JwtDenylist.jti).where(JwtDenylist.jti == str(claims["jti"]))) is not None:
        raise AppError(ErrorCode.AUTH_TOKEN_REVOKED)

    user = db.get(User, user_id)
    if user is None:
        raise AppError(ErrorCode.AUTH_TOKEN_INVALID)

    # 3. REQ-25: emitido antes da última troca de senha.
    if int(claims["iat"]) < int(user.password_changed_at.timestamp()):
        raise AppError(ErrorCode.AUTH_TOKEN_REVOKED)

    # 4. REQ-27: User-Agent precisa ser o mesmo do login.
    if not keyed_hash_matches(user_agent(request), str(claims["ua_hash"])):
        raise AppError(ErrorCode.AUTH_TOKEN_REVOKED)

    # 5. REQ-28: sessão existente, do mesmo usuário e não revogada.
    session = db.get(UserSession, session_id)
    if session is None or session.user_id != user_id or session.revoked_at is not None:
        raise AppError(ErrorCode.AUTH_TOKEN_REVOKED)

    # 6. REQ-26: IP diferente do login não rejeita, só gera alerta.
    check_ip(db, session, str(claims["ip"]), request)

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
