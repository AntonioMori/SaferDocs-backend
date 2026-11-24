"""Log de auditoria (REQ-55/56).

Qualquer parte do sistema registra eventos com:

    audit.record(db, action=AuditAction.DOCUMENT_SIGNED, result=AuditResult.SUCCESS,
                 request=request, user_id=user.id, details={"signature_id": str(sig.id)})

`details` nunca recebe senha, token, chave ou conteúdo de PDF. Como segunda
barreira, chaves com nome sensível e valores binários são substituídos por
"[removido]" antes de gravar (REQ-56).

Campos de todo registro (REQ-56): horário UTC (do banco), IP, User-Agent,
ação e resultado. Sem requisição, IP e User-Agent ficam "desconhecido".
`user_id` só pode faltar nas ações de ANONYMOUS_ACTIONS.

O registro entra na transação de quem chama: é gravado no `commit()` da
operação e desaparece junto se ela for desfeita (um sucesso que não
aconteceu não fica no log). Falhas que encerram a requisição com erro
precisam de `db.commit()` antes do `raise`, como faz o login.

A tabela `audit_log` é append-only (REQ-55): o banco recusa UPDATE,
DELETE e TRUNCATE, então não existe função para alterar ou apagar registros.
"""

import re
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


# Ações que podem acontecer sem usuário identificado (mesma regra do CHECK no banco).
ANONYMOUS_ACTIONS = frozenset({AuditAction.AUTH_FAILURE, AuditAction.DOCUMENT_VERIFIED})

UNKNOWN = "desconhecido"
REDACTED = "[removido]"
_SENSITIVE_KEY = re.compile(
    r"pass|senha|secret|segredo|token|key|chave|code|codigo|otp|cookie|authorization|pdf|content",
    re.IGNORECASE,
)


def _sanitize(value: Any) -> Any:
    """Remove de `details` qualquer coisa que pareça segredo ou conteúdo de arquivo."""
    if isinstance(value, dict):
        return {str(k): REDACTED if _SENSITIVE_KEY.search(str(k)) else _sanitize(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_sanitize(v) for v in value]
    if isinstance(value, bytes | bytearray | memoryview):
        return REDACTED
    return value


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
    action = AuditAction(action)
    if user_id is None and action not in ANONYMOUS_ACTIONS:
        raise ValueError(f"audit.record({action}) exige user_id")
    db.add(
        AuditLog(
            user_id=user_id,
            ip=(client_ip(request) if request is not None else None) or UNKNOWN,
            user_agent=(user_agent(request) if request is not None else None) or UNKNOWN,
            action=action.value,
            result=AuditResult(result).value,
            details=_sanitize(details) if details else None,
        )
    )
