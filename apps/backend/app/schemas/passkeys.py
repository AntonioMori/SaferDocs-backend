"""Schemas das passkeys (REQ-06 a 10).

As credenciais vêm do navegador no formato JSON do WebAuthn (base64url). Os
campos são tipados e limitados: nada de dicionário livre de tamanho qualquer.
"""

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.text_input import clean_text

B64 = r"^[A-Za-z0-9_-]*={0,2}$"
MAX_NAME_LENGTH = 60  # tamanho da coluna webauthn_credentials.name


class _Credential(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str = Field(min_length=1, max_length=1024, pattern=B64)
    rawId: str = Field(min_length=1, max_length=1024, pattern=B64)  # noqa: N815 (nome do WebAuthn)
    type: Literal["public-key"]
    authenticatorAttachment: str | None = Field(default=None, max_length=32)  # noqa: N815
    clientExtensionResults: dict = Field(default_factory=dict)  # noqa: N815


class _AttestationResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    clientDataJSON: str = Field(min_length=1, max_length=4096, pattern=B64)  # noqa: N815
    attestationObject: str = Field(min_length=1, max_length=32768, pattern=B64)  # noqa: N815
    transports: list[str] | None = Field(default=None, max_length=8)


class _AssertionResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    clientDataJSON: str = Field(min_length=1, max_length=4096, pattern=B64)  # noqa: N815
    authenticatorData: str = Field(min_length=1, max_length=4096, pattern=B64)  # noqa: N815
    signature: str = Field(min_length=1, max_length=1024, pattern=B64)
    userHandle: str | None = Field(default=None, max_length=1024, pattern=B64)  # noqa: N815


class RegistrationCredential(_Credential):
    response: _AttestationResponse


class AuthenticationCredential(_Credential):
    response: _AssertionResponse


class PasskeyRegisterIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    credential: RegistrationCredential
    name: str | None = Field(default=None, max_length=240)  # o limite real vale depois de normalizar

    @field_validator("name")
    @classmethod
    def _name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return clean_text(value, min_length=1, max_length=MAX_NAME_LENGTH)  # REQ-64


class PasskeyRenameIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=240)  # o limite real vale depois de normalizar

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        return clean_text(value, min_length=1, max_length=MAX_NAME_LENGTH)  # REQ-64


class PasskeyLoginIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    credential: AuthenticationCredential


class PasskeyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    aaguid: uuid.UUID
    transports: list[str] | None
    created_at: datetime
    last_used_at: datetime | None
