"""Log de auditoria (REQ-55/56).

Qualquer parte do sistema registra eventos com:

    audit.record(db, action=AuditAction.DOCUMENT_SIGNED, result=AuditResult.SUCCESS,
                 request=request, user_id=user.id, details={"signature_id": str(sig.id)})

`details` nunca recebe senha, token, chave ou conteúdo de PDF.

STUB (INFRA-02) | implementação real: REQ-55/56 (dono: AntonioMori).
Hoje só escreve no log da aplicação. A versão real grava na tabela
append-only `audit_log`, com a mesma assinatura.
"""

import logging
import uuid
from enum import StrEnum
from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session

logger = logging.getLogger("saferdocs.audit")


class AuditAction(StrEnum):
    # Eventos obrigatórios do REQ-55
    LOGIN = "LOGIN"
    LOGOUT = "LOGOUT"
    AUTH_FAILURE = "AUTH_FAILURE"
    TOKEN_ISSUED = "TOKEN_ISSUED"
    DOCUMENT_SIGNED = "DOCUMENT_SIGNED"
    DOCUMENT_VERIFIED = "DOCUMENT_VERIFIED"
    PASSWORD_CHANGED = "PASSWORD_CHANGED"
    # Demais eventos de segurança
    USER_REGISTERED = "USER_REGISTERED"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
    TOTP_ENABLED = "TOTP_ENABLED"
    TOTP_DISABLED = "TOTP_DISABLED"
    TOTP_FAILURE = "TOTP_FAILURE"
    RECOVERY_CODE_USED = "RECOVERY_CODE_USED"
    TOKEN_REFRESHED = "TOKEN_REFRESHED"
    REFRESH_TOKEN_REUSE = "REFRESH_TOKEN_REUSE"
    SESSION_REVOKED = "SESSION_REVOKED"
    IP_MISMATCH = "IP_MISMATCH"
    PASSKEY_REGISTERED = "PASSKEY_REGISTERED"
    PASSKEY_REVOKED = "PASSKEY_REVOKED"
    PASSKEY_COUNTER_MISMATCH = "PASSKEY_COUNTER_MISMATCH"


class AuditResult(StrEnum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"


def record(
    db: Session,
    *,
    action: AuditAction,
    result: AuditResult,
    request: Request | None,
    user_id: uuid.UUID | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Acrescenta um registro ao log de auditoria."""
    del db, request  # usados pela implementação real
    logger.info("audit action=%s result=%s user=%s details=%s", action, result, user_id, details)
