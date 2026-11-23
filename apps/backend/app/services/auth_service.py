"""Regras de cadastro e login."""

from fastapi import Request, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import AppError, ErrorCode, FieldError
from app.core.request_info import client_ip
from app.crypto.passwords import dummy_hash, hash_password, needs_rehash, verify_password
from app.db.models import User
from app.middlewares.rate_limit import check_rate_limit
from app.schemas.auth import LoginIn, RegisterIn, TokenOut, UserOut
from app.services import audit_service as audit
from app.services.token_service import issue_tokens
from app.services.user_keys import generate_user_keys


def find_user_by_email(db: Session, email: str) -> User | None:
    return db.scalar(select(User).where(func.lower(User.email) == email.lower()))


def register(db: Session, data: RegisterIn, request: Request) -> User:
    """Cria o usuário com a senha em Argon2id e o par de chaves de assinatura (REQ-45)."""
    if find_user_by_email(db, data.email) is not None:
        raise AppError(ErrorCode.VALIDATION, fields=[FieldError("email", "e-mail já cadastrado")])

    user = User(name=data.name, email=data.email, password_hash=hash_password(data.password))
    db.add(user)
    db.flush()  # gera o id, usado como dado associado na cifragem da chave privada
    generate_user_keys(db, user)
    audit.record(
        db,
        action=audit.AuditAction.USER_REGISTERED,
        result=audit.AuditResult.SUCCESS,
        request=request,
        user_id=user.id,
    )
    db.commit()
    return user


def _invalid_credentials(db: Session, request: Request, user: User | None, reason: str) -> AppError:
    """Registra a falha e devolve SEMPRE o mesmo erro (REQ-04): não diz se foi e-mail ou senha."""
    audit.record(
        db,
        action=audit.AuditAction.AUTH_FAILURE,
        result=audit.AuditResult.FAILURE,
        request=request,
        user_id=user.id if user else None,
        details={"reason": reason},
    )
    db.commit()
    return AppError(ErrorCode.AUTH_INVALID_CREDENTIALS)


def login(db: Session, data: LoginIn, request: Request, response: Response) -> TokenOut:
    """Login com e-mail e senha (Figura 3)."""
    settings = get_settings()
    email = data.email.strip().lower()

    # REQ-05: limites por IP e por conta (implementação no lado B).
    check_rate_limit("login-ip", client_ip(request) or "desconhecido", settings.rate_limit_login_per_ip)
    check_rate_limit("login-account", email, settings.rate_limit_login_per_account)

    user = find_user_by_email(db, email)
    if user is None:
        # Gasta o mesmo tempo de uma verificação real para não revelar que a conta não existe.
        verify_password(dummy_hash(), data.password)
        raise _invalid_credentials(db, request, None, "unknown_user")

    if not verify_password(user.password_hash, data.password):
        raise _invalid_credentials(db, request, user, "wrong_password")

    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(data.password)

    tokens = issue_tokens(db, user, request, response)
    for action in (audit.AuditAction.LOGIN, audit.AuditAction.TOKEN_ISSUED):
        audit.record(db, action=action, result=audit.AuditResult.SUCCESS, request=request, user_id=user.id)
    db.commit()
    return TokenOut(
        access_token=tokens.access_token,
        token_type=tokens.token_type,
        expires_in=tokens.expires_in,
        user=UserOut.model_validate(user),
    )
