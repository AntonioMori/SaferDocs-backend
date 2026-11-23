"""Usuário.

A tabela já nasce com as colunas usadas pelos dois lados do projeto
(identidade/sessão e documentos), para que ninguém precise esperar outra
migration para começar.
"""

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, Index, Integer, LargeBinary, String, Text, func, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin


class User(TimestampMixin, Base):
    __tablename__ = "users"
    __table_args__ = (
        # E-mail único sem diferenciar maiúsculas de minúsculas.
        Index("uq_users_email_lower", func.lower(text("email")), unique=True),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()")
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    email: Mapped[str] = mapped_column(String(254), nullable=False)

    # REQ-02: hash Argon2id; REQ-25: tokens emitidos antes disso são rejeitados.
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    password_changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # REQ-03: bloqueio temporário após falhas consecutivas.
    failed_login_count: Mapped[int] = mapped_column(Integer, server_default=text("0"), nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # REQ-11..15: TOTP (segredo cifrado com AES-GCM; último passo usado evita reuso).
    totp_secret_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    totp_last_step: Mapped[int | None] = mapped_column(BigInteger)

    # REQ-45: chaves de assinatura do usuário (privada sempre cifrada).
    signing_public_key: Mapped[bytes | None] = mapped_column(LargeBinary)
    signing_cert: Mapped[bytes | None] = mapped_column(LargeBinary)
    signing_private_key_enc: Mapped[bytes | None] = mapped_column(LargeBinary)
