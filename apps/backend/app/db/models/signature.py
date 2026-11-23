"""Registro de cada assinatura de PDF (REQ-48/49). O PDF em si nunca é guardado."""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, Numeric, String, Text, func
from sqlalchemy.dialects.postgresql import INET, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Signature(Base):
    __tablename__ = "signatures"

    # Gerado pela aplicação antes de desenhar o selo, pois aparece nele (REQ-47).
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), index=True, nullable=False
    )
    original_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    signed_sha256: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    signed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    ip: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(Text)
    page: Mapped[int] = mapped_column(Integer, nullable=False)
    x: Mapped[float] = mapped_column(Numeric(10, 2), nullable=False)
    y: Mapped[float] = mapped_column(Numeric(10, 2), nullable=False)
