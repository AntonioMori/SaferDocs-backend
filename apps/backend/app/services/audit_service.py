"""Log de auditoria (REQ-55/56).

Qualquer parte do sistema registra eventos com:

    audit.record(db, action=AuditAction.DOCUMENT_SIGNED, result=AuditResult.SUCCESS,
                 request=request, user_id=user.id, details={"signature_id": str(sig.id)})

`details` nunca recebe senha, token, chave ou conteúdo de PDF.

O registro entra na transação de quem chama: é gravado no `commit()` da
operação e desaparece junto se ela for desfeita (um sucesso que não
aconteceu não fica no log). Falhas que encerram a requisição com erro
precisam de `db.commit()` antes do `raise`, como faz o login.

A tabela `audit_log` é append-only (REQ-55): o banco recusa UPDATE,
DELETE e TRUNCATE, então não existe função para alterar ou apagar registros.
"""

import uuid
from enum import StrEnum
from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session

from app.core.request_info import client_ip, user_agent
from app.db.models import AuditLog


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
    db.add(
        AuditLog(
            user_id=user_id,
            ip=client_ip(request) if request is not None else None,
            user_agent=user_agent(request) if request is not None else None,
            action=AuditAction(action).value,
            result=AuditResult(result).value,
            details=details,
        )
    )
