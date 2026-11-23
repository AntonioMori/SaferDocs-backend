"""Auditoria e atividade de segurança (REQ-55, 56 e 58)."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, String, Text, func, text
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AuditLog(Base):
    """Log append-only. Sem FK para users: o registro sobrevive a qualquer mudança."""

    __tablename__ = "audit_log"
    __table_args__ = (Index("ix_audit_log_user_occurred", "user_id", "occurred_at"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    ip: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(Text)
    action: Mapped[str] = mapped_column(String(40), nullable=False)
    result: Mapped[str] = mapped_column(String(10), nullable=False)
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB)


class SecurityEvent(Base):
    """Evento mostrado ao usuário; `seen_at` fica aqui porque o audit log é imutável."""

    __tablename__ = "security_events"
    __table_args__ = (Index("ix_security_events_user_seen", "user_id", "seen_at"),)

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    type: Mapped[str] = mapped_column(String(40), nullable=False)
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class KnownIp(Base):
    """IPs já vistos por usuário, para detectar login de IP desconhecido (REQ-58)."""

    __tablename__ = "known_ips"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    ip_hmac: Mapped[str] = mapped_column(String(64), primary_key=True)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
