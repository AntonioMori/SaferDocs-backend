"""Dependências compartilhadas pelas rotas.

`get_current_user` é a porta de entrada de toda rota autenticada. Rotas
protegidas devem usá-la no router inteiro, não rota a rota:

    router = APIRouter(dependencies=[Depends(get_current_user)])

STUB (INFRA-02) | implementação real: REQ-22 (dono: AntonioMori).
Hoje valida assinatura, emissor e expiração do JWT e carrega o usuário.
O REQ-22 acrescenta, sem mudar a assinatura: denylist, troca de senha,
User-Agent, sessão revogada e alerta de IP (Figura 4).
Para testar rotas protegidas antes disso: `uv run python scripts/dev_token.py`.
"""

import uuid
from typing import Annotated

import jwt
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.errors import AppError, ErrorCode
from app.crypto.jwt import decode_access_token
from app.db.models import User
from app.db.session import get_db

_bearer = HTTPBearer(auto_error=False)

DbSession = Annotated[Session, Depends(get_db)]


def get_current_user(
    request: Request,
    db: DbSession,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> User:
    """Usuário dono do access token. Lança ErrorCode.AUTH_TOKEN_INVALID se o token for ausente ou inválido."""
    if credentials is None:
        raise AppError(ErrorCode.AUTH_TOKEN_INVALID)
    try:
        claims = decode_access_token(credentials.credentials)
        user_id = uuid.UUID(claims["sub"])
    except (jwt.PyJWTError, ValueError):
        raise AppError(ErrorCode.AUTH_TOKEN_INVALID) from None

    user = db.get(User, user_id)
    if user is None:
        raise AppError(ErrorCode.AUTH_TOKEN_INVALID)
    request.state.token_claims = claims
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]
