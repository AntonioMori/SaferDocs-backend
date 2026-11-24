"""Schemas do segundo fator (REQ-13 e REQ-14)."""

from pydantic import BaseModel, ConfigDict, Field


class TotpSetupOut(BaseModel):
    otpauth_uri: str  # o front gera o QR Code a partir desta URI
    secret: str  # para digitar no app quando não der para ler o QR


class TotpCodeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(min_length=6, max_length=10)


class TotpDisableIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    password: str = Field(min_length=1, max_length=1024)
    code: str = Field(min_length=6, max_length=10)


class TotpEnabledOut(BaseModel):
    recovery_codes: list[str]  # mostrados uma única vez (REQ-14)
