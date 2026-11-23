"""Passkeys (REQ-06..10)."""

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, LargeBinary, String, func, text
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class WebauthnCredential(Base):
    """Dispositivo registrado. Os quatro campos do REQ-07 são obrigatórios."""

    __tablename__ = "webauthn_credentials"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    credential_id: Mapped[bytes] = mapped_column(LargeBinary, unique=True, nullable=False)
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    counter: Mapped[int] = mapped_column(BigInteger, server_default=text("0"), nullable=False)
    aaguid: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    name: Mapped[str] = mapped_column(String(60), nullable=False)
    transports: Mapped[list[str] | None] = mapped_column(ARRAY(String(20)))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class WebauthnChallenge(Base):
    """Desafio de uma cerimônia, de uso único e curta duração."""

    __tablename__ = "webauthn_challenges"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    challenge: Mapped[bytes] = mapped_column(LargeBinary, unique=True, nullable=False)
    kind: Mapped[str] = mapped_column(String(10), nullable=False)  # "register" | "login"
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
