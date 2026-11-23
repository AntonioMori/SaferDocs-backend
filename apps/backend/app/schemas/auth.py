"""Schemas de entrada e saída da autenticação."""

import uuid

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.core.password_policy import password_policy_violations


def check_password_policy(value: str) -> str:
    """Validador Pydantic reutilizado no cadastro e na troca de senha (REQ-01)."""
    violations = password_policy_violations(value)
    if violations:
        raise ValueError("; ".join(violations))
    return value


class RegisterIn(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)

    name: str = Field(min_length=2, max_length=120)
    email: EmailStr = Field(max_length=254)
    password: str

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        value = " ".join(value.split())
        if len(value) < 2:
            raise ValueError("mínimo de 2 caracteres")
        return value

    @field_validator("email")
    @classmethod
    def _email(cls, value: str) -> str:
        return value.lower()

    @field_validator("password")
    @classmethod
    def _password(cls, value: str) -> str:
        return check_password_policy(value)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    email: str
