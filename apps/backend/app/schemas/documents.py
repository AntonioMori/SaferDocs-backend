"""Schemas das assinaturas de documentos (REQ-48/49). Nunca incluem chave nem o PDF."""

import uuid
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel


class SignatureOut(BaseModel):
    id: uuid.UUID
    original_sha256: str
    signed_sha256: str
    signed_at: datetime
    page: int
    x: float
    y: float


class VerificationStatus(StrEnum):
    INTEGRO = "INTEGRO"  # documento íntegro
    ADULTERADO = "ADULTERADO"  # documento adulterado
    NAO_ENCONTRADA = "NAO_ENCONTRADA"  # assinatura não encontrada


class VerificationOut(BaseModel):
    """Resultado da verificação pública (REQ-52). Os detalhes só vêm quando o documento é íntegro."""

    status: VerificationStatus
    signer_name: str | None = None
    signed_at: datetime | None = None
    signature_id: uuid.UUID | None = None
