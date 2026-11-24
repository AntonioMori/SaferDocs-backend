"""Ativação e desativação do 2FA com TOTP (REQ-13). Todas as rotas exigem autenticação."""

from fastapi import APIRouter, Depends, Request, Response, status

from app.api.deps import CurrentUser, DbSession, get_current_user
from app.schemas.twofa import TotpCodeIn, TotpDisableIn, TotpEnabledOut, TotpSetupOut
from app.services import totp_service

router = APIRouter(prefix="/auth/2fa", tags=["2fa"], dependencies=[Depends(get_current_user)])


@router.post("/setup", response_model=TotpSetupOut)
def setup(user: CurrentUser, db: DbSession) -> TotpSetupOut:
    """Gera o segredo e a URI `otpauth://` para o QR Code. Ainda não ativa o 2FA."""
    return totp_service.start_setup(db, user)


@router.post("/enable", response_model=TotpEnabledOut)
def enable(data: TotpCodeIn, user: CurrentUser, request: Request, db: DbSession) -> TotpEnabledOut:
    """Confirma com um código do app e ativa o 2FA."""
    return totp_service.confirm_setup(db, user, data.code, request)


@router.post("/disable", status_code=status.HTTP_204_NO_CONTENT)
def disable(data: TotpDisableIn, user: CurrentUser, request: Request, db: DbSession) -> Response:
    """Desativa o 2FA (exige senha e código)."""
    totp_service.disable(db, user, data.password, data.code, request)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
