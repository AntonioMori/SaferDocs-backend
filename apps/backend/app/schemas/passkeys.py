"""Schemas das passkeys (REQ-06 a 10).

As credenciais vêm do navegador no formato JSON do WebAuthn (base64url). Os
campos são tipados e limitados: nada de dicionário livre de tamanho qualquer.
"""

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

B64 = r"^[A-Za-z0-9_-]*={0,2}$"


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
    name: str | None = Field(default=None, max_length=120)


class PasskeyLoginIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    credential: AuthenticationCredential


class PasskeyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    created_at: datetime
