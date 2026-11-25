"""Passkeys (REQ-06 a 10).

Registro: autenticado (o usuário já entrou com senha e cadastra o dispositivo).
Login: público, com rate limit por IP como o login com senha (REQ-05).
"""

from typing import Any

from fastapi import APIRouter, Depends, Request, Response, status

from app.api.deps import CurrentUser, DbSession, get_auth_context
from app.core.config import get_settings
from app.core.request_info import client_ip
from app.middlewares.rate_limit import check_rate_limit
from app.schemas.auth import TokenOut
from app.schemas.passkeys import PasskeyLoginIn, PasskeyOut, PasskeyRegisterIn
from app.services import passkey_service

router = APIRouter(prefix="/auth/passkeys", tags=["passkeys"])


def limit_passkey_login_by_ip(request: Request) -> None:
    check_rate_limit(
        "login-passkey-ip", client_ip(request) or "desconhecido", get_settings().rate_limit_login_per_ip
    )


@router.post("/register/options", dependencies=[Depends(get_auth_context)])
def registration_options(user: CurrentUser, db: DbSession) -> dict[str, Any]:
    """Opções para o `navigator.credentials.create` (JSON do WebAuthn)."""
    return passkey_service.registration_options(db, user)


@router.post(
    "/register/verify",
    response_model=PasskeyOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(get_auth_context)],
)
def register_verify(
    data: PasskeyRegisterIn, user: CurrentUser, request: Request, db: DbSession
) -> PasskeyOut:
    """Confere a credencial criada pelo navegador e guarda o dispositivo."""
    credential = data.credential.model_dump(exclude_none=True)
    stored = passkey_service.register_credential(db, user, credential, request, data.name)
    return PasskeyOut.model_validate(stored)


@router.post("/login/options", dependencies=[Depends(limit_passkey_login_by_ip)])
def login_options(db: DbSession) -> dict[str, Any]:
    """Opções para o `navigator.credentials.get`, sem e-mail (credencial descobrível)."""
    return passkey_service.authentication_options(db)


@router.post("/login/verify", response_model=TokenOut, dependencies=[Depends(limit_passkey_login_by_ip)])
def login_verify(data: PasskeyLoginIn, request: Request, response: Response, db: DbSession) -> TokenOut:
    """Confere a asserção e faz o login (access token + cookie de refresh, como o login com senha)."""
    return passkey_service.authenticate(db, data.credential.model_dump(exclude_none=True), request, response)
