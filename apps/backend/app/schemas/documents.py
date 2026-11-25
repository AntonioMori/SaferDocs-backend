"""Schemas das assinaturas de documentos (REQ-48/49). Nunca incluem chave nem o PDF."""

import uuid
from datetime import datetime

from pydantic import BaseModel


class SignatureOut(BaseModel):
    id: uuid.UUID
    original_sha256: str
    signed_sha256: str
    signed_at: datetime
    page: int
    x: float
    y: float
