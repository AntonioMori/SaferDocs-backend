"""Configuração da aplicação (RNF-05).

Tudo o que é sensível ou depende do ambiente vem de variáveis de ambiente
ou do arquivo `.env`. Nada disso é escrito no código. A lista completa e
documentada está em `.env.example`.
"""

from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- Aplicação
    app_env: Literal["development", "test", "production"] = "development"

    # --- Banco de dados
    database_url: SecretStr

    # --- JWT (REQ-17/18): par ES256 em PEM, codificado em base64 numa linha
    jwt_private_key_pem_b64: SecretStr
    jwt_public_key_pem_b64: str
    jwt_issuer: str = "saferdocs"
    access_token_ttl_seconds: int = Field(default=900, gt=0)
    refresh_token_ttl_seconds: int = Field(default=604800, gt=0)

    # --- Segredos do sistema (base64 de 32 bytes)
    master_key: SecretStr  # deriva as chaves que cifram TOTP e chaves de assinatura
    hash_pepper: SecretStr  # chave HMAC para IP, User-Agent e códigos de recuperação

    # --- CORS (REQ-31..36)
    cors_allowed_origins: Annotated[list[str], NoDecode]
    cors_max_age_seconds: int = Field(default=600, ge=0)

    # --- WebAuthn (REQ-09)
    webauthn_rp_id: str
    webauthn_rp_name: str = "SaferDocs"
    webauthn_origin: str

    # --- Login (REQ-03/05)
    login_max_attempts: int = Field(default=5, gt=0)
    login_lock_minutes: int = Field(default=15, gt=0)
    rate_limit_login_per_ip: str = "10/minute"
    rate_limit_login_per_account: str = "5/minute"
    rate_limit_verify_per_ip: str = "10/minute"

    # --- PDF (REQ-61/62)
    max_upload_mb: int = Field(default=20, gt=0)
    pdf_worker_socket: str = "/run/pdf/worker.sock"
    pdf_worker_timeout_seconds: int = Field(default=30, gt=0)

    # --- Cookies (REQ-20)
    cookie_secure: bool = True

    @field_validator("cors_allowed_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"


@lru_cache
def get_settings() -> Settings:
    """Settings carregadas uma única vez por processo."""
    return Settings()  # type: ignore[call-arg]
