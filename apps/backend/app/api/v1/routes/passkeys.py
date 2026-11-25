"""Passkeys (REQ-06 a 10).

Registro: autenticado (o usuário já entrou com senha e cadastra o dispositivo).
Login: público, com rate limit por IP como o login com senha (REQ-05), um escopo para
`options` e outro para `verify`. Registro: rate limit por usuário, também um escopo por rota.
"""

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Request, Response, status

from app.api.deps import CurrentUser, DbSession, get_auth_context
from app.core.config import get_settings
from app.core.request_info import client_ip
from app.middlewares.rate_limit import check_rate_limit, ip_bucket
from app.schemas.auth import TokenOut
from app.schemas.passkeys import PasskeyLoginIn, PasskeyOut, PasskeyRegisterIn, PasskeyRenameIn
from app.services import passkey_service

router = APIRouter(prefix="/auth/passkeys", tags=["passkeys"])


def limit_passkey_login_options(request: Request) -> None:
    check_rate_limit(
        "passkey-login-options", ip_bucket(client_ip(request)), get_settings().rate_limit_login_per_ip
    )


def limit_passkey_login_verify(request: Request) -> None:
    # Escopo próprio: um login gasta uma vaga em cada rota, e encher o `options` não trava o `verify`.
    check_rate_limit(
        "passkey-login-verify", ip_bucket(client_ip(request)), get_settings().rate_limit_login_per_ip
    )


def limit_passkey_register_options(user: CurrentUser) -> None:
    check_rate_limit(
        "passkey-register-options", str(user.id), get_settings().rate_limit_passkey_register_per_user
    )


def limit_passkey_register_verify(user: CurrentUser) -> None:
    check_rate_limit(
        "passkey-register-verify", str(user.id), get_settings().rate_limit_passkey_register_per_user
    )


@router.post(
    "/register/options",
    dependencies=[Depends(get_auth_context), Depends(limit_passkey_register_options)],
)
def registration_options(user: CurrentUser, db: DbSession) -> dict[str, Any]:
    """Opções para o `navigator.credentials.create` (JSON do WebAuthn)."""
    return passkey_service.registration_options(db, user)


@router.post(
    "/register/verify",
    response_model=PasskeyOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(get_auth_context), Depends(limit_passkey_register_verify)],
)
def register_verify(
    data: PasskeyRegisterIn, user: CurrentUser, request: Request, db: DbSession
) -> PasskeyOut:
    """Confere a credencial criada pelo navegador e guarda o dispositivo."""
    credential = data.credential.model_dump(exclude_none=True)
    stored = passkey_service.register_credential(db, user, credential, request, data.name)
    return PasskeyOut.model_validate(stored)


@router.post("/login/options", dependencies=[Depends(limit_passkey_login_options)])
def login_options(db: DbSession) -> dict[str, Any]:
    """Opções para o `navigator.credentials.get`, sem e-mail (credencial descobrível)."""
    return passkey_service.authentication_options(db)


@router.post("/login/verify", response_model=TokenOut, dependencies=[Depends(limit_passkey_login_verify)])
def login_verify(data: PasskeyLoginIn, request: Request, response: Response, db: DbSession) -> TokenOut:
    """Confere a asserção e faz o login (access token + cookie de refresh, como o login com senha)."""
    return passkey_service.authenticate(db, data.credential.model_dump(exclude_none=True), request, response)


# Gerenciamento (REQ-10): só o dono enxerga e mexe nas próprias passkeys.


@router.get("", response_model=list[PasskeyOut], dependencies=[Depends(get_auth_context)])
def list_passkeys(user: CurrentUser, db: DbSession) -> list[PasskeyOut]:
    """Dispositivos do usuário, sem chave pública nem contador."""
    return [PasskeyOut.model_validate(p) for p in passkey_service.list_credentials(db, user)]


@router.put("/{passkey_id}", response_model=PasskeyOut, dependencies=[Depends(get_auth_context)])
def rename_passkey(
    passkey_id: uuid.UUID, data: PasskeyRenameIn, user: CurrentUser, request: Request, db: DbSession
) -> PasskeyOut:
    """Renomeia um dispositivo. De outro usuário ou inexistente: 404."""
    stored = passkey_service.rename_credential(db, user, passkey_id, data.name, request)
    return PasskeyOut.model_validate(stored)


@router.delete(
    "/{passkey_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(get_auth_context)]
)
def revoke_passkey(passkey_id: uuid.UUID, user: CurrentUser, request: Request, db: DbSession) -> Response:
    """Revoga um dispositivo: ele não autentica mais."""
    passkey_service.revoke_credential(db, user, passkey_id, request)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
