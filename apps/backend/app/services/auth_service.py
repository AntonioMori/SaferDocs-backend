"""Regras de cadastro e login."""

from fastapi import Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.errors import AppError, ErrorCode, FieldError
from app.crypto.passwords import hash_password
from app.db.models import User
from app.schemas.auth import RegisterIn
from app.services import audit_service as audit
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
