"""Rotas de autenticação: cadastro e login."""

from fastapi import APIRouter, Request, Response, status

from app.api.deps import DbSession
from app.schemas.auth import LoginIn, RegisterIn, TokenOut, UserOut
from app.services import auth_service

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", status_code=status.HTTP_201_CREATED, response_model=UserOut)
def register(data: RegisterIn, request: Request, db: DbSession) -> UserOut:
    """Cadastra um usuário. A senha precisa cumprir a política do REQ-01."""
    return UserOut.model_validate(auth_service.register(db, data, request))


@router.post("/login", response_model=TokenOut)
def login(data: LoginIn, request: Request, response: Response, db: DbSession) -> TokenOut:
    """Login com e-mail e senha. Qualquer falha devolve a mesma mensagem (REQ-04)."""
    return auth_service.login(db, data, request, response)
