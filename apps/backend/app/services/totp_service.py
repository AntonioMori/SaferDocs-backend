"""Segundo fator com TOTP (REQ-11 a 16).

O segredo tem 160 bits (20 bytes do CSPRNG, o tamanho recomendado pela
RFC 4226) e fica no banco cifrado com AES-256-GCM, com chave derivada da
MASTER_KEY só para este uso e o id do usuário como dado associado: o valor
cifrado de uma conta não pode ser copiado para outra (REQ-12).
"""

import base64
import secrets
import uuid
from datetime import UTC, datetime, timedelta

import pyotp
from fastapi import Request
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core.errors import AppError, ErrorCode, FieldError
from app.crypto import totp
from app.crypto.aead import AeadContext, decrypt, encrypt
from app.crypto.keyed_hash import keyed_hash
from app.crypto.passwords import verify_password
from app.db.models import AuditLog, RecoveryCode, SecurityEvent, User
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
    codes = generate_recovery_codes(db, user)
    db.commit()
    return TotpEnabledOut(recovery_codes=codes)


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


# ---------------------------------------------------------------- códigos de recuperação (REQ-14)

RECOVERY_CODE_COUNT = 10
RECOVERY_CODE_GROUPS = 3
RECOVERY_CODE_GROUP_SIZE = 4
# Sem 0/O, 1/I/L: fácil de copiar à mão. 31 símbolos x 12 posições ~ 59 bits por código.
RECOVERY_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


def _normalize_recovery_code(code: str) -> str:
    return "".join(ch for ch in code.upper() if ch.isalnum())


def _recovery_hmac(code: str) -> str:
    """HMAC com o HASH_PEPPER: o código tem entropia alta, não precisa de Argon2."""
    return keyed_hash("recovery:" + _normalize_recovery_code(code))


def generate_recovery_codes(db: Session, user: User) -> list[str]:
    """Troca todos os códigos do usuário por 10 novos. Devolve os códigos em claro uma única vez."""
    db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user.id))
    codes = [
        "-".join(
            "".join(secrets.choice(RECOVERY_ALPHABET) for _ in range(RECOVERY_CODE_GROUP_SIZE))
            for _ in range(RECOVERY_CODE_GROUPS)
        )
        for _ in range(RECOVERY_CODE_COUNT)
    ]
    db.add_all(RecoveryCode(user_id=user.id, code_hmac=_recovery_hmac(code)) for code in codes)
    db.flush()
    return codes


def use_recovery_code(db: Session, user: User, code: str) -> bool:
    """Consome um código de recuperação. Código já usado ou de outra conta não vale."""
    if len(_normalize_recovery_code(code)) != RECOVERY_CODE_GROUPS * RECOVERY_CODE_GROUP_SIZE:
        return False
    registro = db.scalar(
        select(RecoveryCode)
        .where(
            RecoveryCode.user_id == user.id,
            RecoveryCode.code_hmac == _recovery_hmac(code),
            RecoveryCode.used_at.is_(None),
        )
        .with_for_update()
    )
    if registro is None:
        return False
    registro.used_at = datetime.now(UTC)
    return True


def regenerate_recovery_codes(db: Session, user: User, code: str, request: Request) -> TotpEnabledOut:
    """Gera um conjunto novo (os antigos deixam de valer). Exige um código TOTP válido."""
    if not user.totp_enabled:
        raise _invalid("totp", "a verificação em duas etapas não está ativa")
    step = totp.verify(load_secret(user) or "", code, user.totp_last_step)
    if step is None:
        raise _invalid("code", "código inválido")
    user.totp_last_step = step
    codes = generate_recovery_codes(db, user)
    audit.record(
        db,
        action=audit.AuditAction.RECOVERY_CODES_REGENERATED,
        result=audit.AuditResult.SUCCESS,
        request=request,
        user_id=user.id,
    )
    db.commit()
    return TotpEnabledOut(recovery_codes=codes)


# ---------------------------------------------------------------- alerta de códigos inválidos (REQ-16)

FAILURE_ALERT_THRESHOLD = 3
FAILURE_ALERT_WINDOW = timedelta(minutes=15)


def alert_on_repeated_failures(db: Session, user_id: uuid.UUID, request: Request) -> bool:
    """Depois de registrar um TOTP_FAILURE: com 3 falhas em 15 min, avisa o usuário.

    Um alerta por janela: enquanto houver um TOTP_FAILURES nos últimos 15 min,
    novas falhas não geram outro. Retorna True se emitiu.
    """
    db.flush()  # a falha que acabou de ser registrada também conta (a sessão não usa autoflush)
    desde = datetime.now(UTC) - FAILURE_ALERT_WINDOW
    falhas = db.scalar(
        select(func.count()).where(
            AuditLog.user_id == user_id,
            AuditLog.action == audit.AuditAction.TOTP_FAILURE,
            AuditLog.occurred_at >= desde,
        )
    )
    if falhas < FAILURE_ALERT_THRESHOLD:
        return False
    ja_avisado = db.scalar(
        select(SecurityEvent.id).where(
            SecurityEvent.user_id == user_id,
            SecurityEvent.type == SecurityEventType.TOTP_FAILURES,
            SecurityEvent.created_at >= desde,
        )
    )
    if ja_avisado is not None:
        return False
    security_events.emit(
        db,
        user_id=user_id,
        type=SecurityEventType.TOTP_FAILURES,
        request=request,
        details={"failures": falhas, "window_minutes": int(FAILURE_ALERT_WINDOW.total_seconds() // 60)},
    )
    return True
