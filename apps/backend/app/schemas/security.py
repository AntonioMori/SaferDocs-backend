"""Schemas da atividade de segurança (REQ-58)."""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class SecurityEventOut(BaseModel):
    id: uuid.UUID
    type: str
    created_at: datetime
    seen: bool
    details: dict[str, Any] | None


class MarkSeenIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ids: list[uuid.UUID] = Field(min_length=1, max_length=100)
