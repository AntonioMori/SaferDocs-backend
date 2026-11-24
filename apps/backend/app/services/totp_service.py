"""Segundo fator com TOTP (REQ-11 a 16).

O segredo tem 160 bits (20 bytes do CSPRNG, o tamanho recomendado pela
RFC 4226) e fica no banco cifrado com AES-256-GCM, com chave derivada da
MASTER_KEY só para este uso e o id do usuário como dado associado: o valor
cifrado de uma conta não pode ser copiado para outra (REQ-12).
"""

import base64
import secrets

import pyotp
from fastapi import Request
from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.core.errors import AppError, ErrorCode, FieldError
from app.crypto import totp
from app.crypto.aead import AeadContext, decrypt, encrypt
from app.crypto.passwords import verify_password
from app.db.models import RecoveryCode, User
from app.schemas.twofa import TotpEnabledOut, TotpSetupOut
from app.services import audit_service as audit
from app.services import security_events
from app.services.security_events import SecurityEventType

SECRET_BYTES = 20  # 160 bits


def generate_secret() -> str:
    """Segredo novo em base32, o formato que os apps autenticadores leem."""
    return base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode()


def store_secret(user: User, secret_b32: str) -> None:
    user.totp_secret_enc = encrypt(
        AeadContext.TOTP_SECRET, secret_b32.encode(), associated_data=user.id.bytes
    )


def load_secret(user: User) -> str | None:
    if user.totp_secret_enc is None:
        return None
    return decrypt(AeadContext.TOTP_SECRET, user.totp_secret_enc, associated_data=user.id.bytes).decode()


# ---------------------------------------------------------------- ativação e desativação (REQ-13)

ISSUER = "SaferDocs"


def _invalid(field: str, reason: str) -> AppError:
    return AppError(ErrorCode.VALIDATION, fields=[FieldError(field, reason)])


def provisioning_uri(user: User, secret_b32: str) -> str:
    """URI `otpauth://totp/...` que o front transforma em QR Code."""
    return pyotp.TOTP(secret_b32, digits=totp.DIGITS, interval=totp.INTERVAL_SECONDS).provisioning_uri(
        name=user.email, issuer_name=ISSUER
    )


def start_setup(db: Session, user: User) -> TotpSetupOut:
    """Gera um segredo pendente. O 2FA só passa a valer depois do `confirm_setup`."""
    if user.totp_enabled:
        raise _invalid("totp", "a verificação em duas etapas já está ativa")
    secret = generate_secret()
    store_secret(user, secret)
    user.totp_last_step = None
    db.commit()
    return TotpSetupOut(otpauth_uri=provisioning_uri(user, secret), secret=secret)


def confirm_setup(db: Session, user: User, code: str, request: Request) -> TotpEnabledOut:
    """Ativa o 2FA só se o código do app bater com o segredo pendente (prova que o QR foi lido)."""
    if user.totp_enabled:
        raise _invalid("totp", "a verificação em duas etapas já está ativa")
    secret = load_secret(user)
    if secret is None:
        raise _invalid("totp", "inicie a ativação antes de confirmar")
    step = totp.verify(secret, code, user.totp_last_step)
    if step is None:
        raise _invalid("code", "código inválido")

    user.totp_enabled = True
    user.totp_last_step = step
    audit.record(
        db,
        action=audit.AuditAction.TOTP_ENABLED,
        result=audit.AuditResult.SUCCESS,
        request=request,
        user_id=user.id,
    )
    security_events.emit(db, user_id=user.id, type=SecurityEventType.TOTP_ENABLED, request=request)
    db.commit()
    return TotpEnabledOut(recovery_codes=[])


def disable(db: Session, user: User, password: str, code: str, request: Request) -> None:
    """Desativa o 2FA. Exige a senha e um código válido, para um token roubado não bastar."""
    if not user.totp_enabled:
        raise _invalid("totp", "a verificação em duas etapas não está ativa")
    if not verify_password(user.password_hash, password):
        raise _invalid("password", "senha incorreta")
    if totp.verify(load_secret(user) or "", code, user.totp_last_step) is None:
        raise _invalid("code", "código inválido")

    user.totp_enabled = False
    user.totp_secret_enc = None
    user.totp_last_step = None
    db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user.id))
    audit.record(
        db,
        action=audit.AuditAction.TOTP_DISABLED,
        result=audit.AuditResult.SUCCESS,
        request=request,
        user_id=user.id,
    )
    security_events.emit(db, user_id=user.id, type=SecurityEventType.TOTP_DISABLED, request=request)
    db.commit()
