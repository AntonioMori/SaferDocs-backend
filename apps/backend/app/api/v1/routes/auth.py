"""Rotas de autenticação: cadastro, login, troca de senha e logout."""

from fastapi import APIRouter, Request, Response, status

from app.api.deps import CurrentAuth, DbSession
from app.schemas.auth import ChangePasswordIn, LoginIn, RegisterIn, TokenOut, UserOut
from app.services import auth_service, session_service

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", status_code=status.HTTP_201_CREATED, response_model=UserOut)
def register(data: RegisterIn, request: Request, db: DbSession) -> UserOut:
    """Cadastra um usuário. A senha precisa cumprir a política do REQ-01."""
    return UserOut.model_validate(auth_service.register(db, data, request))


@router.post("/login", response_model=TokenOut)
def login(data: LoginIn, request: Request, response: Response, db: DbSession) -> TokenOut:
    """Login com e-mail e senha. Qualquer falha devolve a mesma mensagem (REQ-04)."""
    return auth_service.login(db, data, request, response)


@router.post("/refresh", response_model=TokenOut)
def refresh(request: Request, response: Response, db: DbSession) -> TokenOut:
    """Troca o refresh token do cookie por um par novo; o anterior deixa de valer (REQ-29)."""
    return session_service.refresh(db, request, response)


@router.put("/password", response_model=TokenOut)
def change_password(
    data: ChangePasswordIn, context: CurrentAuth, request: Request, response: Response, db: DbSession
) -> TokenOut:
    """Troca a senha. Todas as sessões anteriores são encerradas e um novo par é emitido (REQ-25)."""
    return session_service.change_password(db, context, data, request, response)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(context: CurrentAuth, request: Request, response: Response, db: DbSession) -> Response:
    """Encerra a sessão atual: o access token vai para a denylist (REQ-21)."""
    session_service.logout(db, context, request, response)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response
