"""Atividade de segurança mostrada ao usuário (REQ-58, REQ-16, REQ-26).

    security_events.emit(db, user_id=user.id, type=SecurityEventType.PASSWORD_CHANGED,
                         request=request)

Cada evento fica em `security_events` até o usuário marcá-lo como visto.
O `seen_at` mora aqui, e não no audit log, porque o audit log é imutável.
Eventos não vistos voltam no próximo login (`unseen_security_events` na
resposta) para o front destacá-los.

`emit` não grava no audit log: quem chama registra a própria ação lá. Como
`audit.record`, entra na transação de quem chama (não faz commit).
"""

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from fastapi import Request
from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core.request_info import client_ip, user_agent
from app.crypto.keyed_hash import keyed_hash
from app.db.models import KnownIp, SecurityEvent
from app.services.audit_service import sanitize_details

MAX_LISTED = 100


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
    """Registra um evento de segurança para o usuário ver.

    A origem da requisição (IP e navegador) vai junto, para o usuário
    reconhecer se foi ele.
    """
    dados = dict(sanitize_details(details) or {})
    if request is not None:
        dados.setdefault("ip", client_ip(request))
        dados.setdefault("user_agent", user_agent(request))
    db.add(SecurityEvent(user_id=user_id, type=SecurityEventType(type).value, details=dados or None))


def check_login_ip(db: Session, user_id: uuid.UUID, request: Request) -> bool:
    """REQ-58: avisa quando o login vem de um IP que a conta nunca usou.

    Guarda só o HMAC do IP. O primeiro IP conhecido (cadastro, ou o primeiro
    login de contas anteriores a este requisito) não gera alerta.
    Retorna True se o alerta foi emitido.
    """
    ip_hmac = keyed_hash(client_ip(request) or "")
    ja_tinha_ips = db.scalar(select(KnownIp.ip_hmac).where(KnownIp.user_id == user_id).limit(1)) is not None
    inserido = db.scalar(
        insert(KnownIp)
        .values(user_id=user_id, ip_hmac=ip_hmac)
        .on_conflict_do_nothing(index_elements=["user_id", "ip_hmac"])
        .returning(KnownIp.ip_hmac)
    )
    if inserido is not None and ja_tinha_ips:
        emit(db, user_id=user_id, type=SecurityEventType.NEW_IP_LOGIN, request=request)
        return True
    return False


def unseen_count(db: Session, user_id: uuid.UUID) -> int:
    return db.scalar(
        select(func.count()).where(SecurityEvent.user_id == user_id, SecurityEvent.seen_at.is_(None))
    )


def list_events(db: Session, user_id: uuid.UUID) -> list[SecurityEvent]:
    """Os eventos mais recentes do usuário, os não vistos primeiro."""
    return list(
        db.scalars(
            select(SecurityEvent)
            .where(SecurityEvent.user_id == user_id)
            .order_by(SecurityEvent.seen_at.is_not(None), SecurityEvent.created_at.desc())
            .limit(MAX_LISTED)
        )
    )


def mark_seen(db: Session, user_id: uuid.UUID, ids: list[uuid.UUID]) -> None:
    """Marca como vistos. Ids de outro usuário ou inexistentes são ignorados."""
    if ids:
        db.execute(
            update(SecurityEvent)
            .where(
                SecurityEvent.user_id == user_id,
                SecurityEvent.id.in_(ids),
                SecurityEvent.seen_at.is_(None),
            )
            .values(seen_at=datetime.now(UTC))
        )
    db.commit()
