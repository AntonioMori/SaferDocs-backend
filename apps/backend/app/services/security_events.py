"""Atividade de segurança mostrada ao usuário (REQ-58, REQ-16, REQ-26).

    security_events.emit(db, user_id=user.id, type=SecurityEventType.PASSWORD_CHANGED,
                         request=request)

STUB (INFRA-02) | implementação real: REQ-58 (dono: AntonioMori).
Hoje não faz nada. A versão real grava em `security_events` (e no audit
log) para o evento aparecer em destaque no próximo login.
"""

import uuid
from enum import StrEnum
from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session


class SecurityEventType(StrEnum):
    NEW_IP_LOGIN = "NEW_IP_LOGIN"
    TOTP_ENABLED = "TOTP_ENABLED"
    TOTP_DISABLED = "TOTP_DISABLED"
    PASSWORD_CHANGED = "PASSWORD_CHANGED"
    TOTP_FAILURES = "TOTP_FAILURES"
    IP_CHANGED = "IP_CHANGED"
    REFRESH_TOKEN_REUSE = "REFRESH_TOKEN_REUSE"
    PASSKEY_COUNTER_MISMATCH = "PASSKEY_COUNTER_MISMATCH"


def emit(
    db: Session,
    *,
    user_id: uuid.UUID,
    type: SecurityEventType,  # noqa: A002 (nome do contrato)
    request: Request | None,
    details: dict[str, Any] | None = None,
) -> None:
    """Registra um evento de segurança para o usuário ver."""
    del db, user_id, type, request, details  # usados pela implementação real
