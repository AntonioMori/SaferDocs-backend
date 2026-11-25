"""Configuração da aplicação (RNF-05 e RNF-08).

Tudo o que é sensível ou depende do ambiente vem de variáveis de ambiente
ou do arquivo `.env`. Nada disso é escrito no código. A lista completa e
documentada está em `.env.example`.

Na inicialização todas as variáveis são validadas (RNF-08). Se alguma
obrigatória faltar ou for inválida, a aplicação não sobe e mostra quais
variáveis estão erradas, sem nunca imprimir o valor delas.
"""

import base64
import binascii
import ipaddress
import re
from functools import lru_cache
from typing import Annotated, Literal
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import Field, SecretStr, ValidationError, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

RATE_LIMIT_PATTERN = re.compile(r"^\d+/(second|minute|hour)$")


class ConfigError(RuntimeError):
    """Configuração ausente ou inválida. A mensagem nunca contém valores."""


def _decode_b64(value: str, name: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError(f"{name} precisa estar em base64") from None


DEFAULT_PORTS = {"http": 80, "https": 443}
_HOST_CHARS = re.compile(r"^[a-z0-9._-]+$")
_NUMERIC_HOST = re.compile(r"^[0-9.]+$")


def _invalid(origin: str, motivo: str = "use esquema://host[:porta]") -> ValueError:
    return ValueError(f"origem inválida: {origin!r} ({motivo})")


def _canonical_host(origin: str, hostname: str) -> str:
    """Host como o navegador escreve no `Origin`: punycode, IP canônico, minúsculas."""
    if ":" in hostname:  # IPv6
        try:
            return f"[{ipaddress.IPv6Address(hostname).compressed}]"
        except ValueError:
            raise _invalid(origin, "IPv6 inválido") from None
    if _NUMERIC_HOST.match(hostname):
        # O navegador reescreve atalhos como 127.1; exigimos a forma completa.
        try:
            return str(ipaddress.IPv4Address(hostname))
        except ValueError:
            raise _invalid(origin, "IPv4 inválido") from None
    try:
        host = hostname.encode("idna").decode("ascii").lower()  # bücher -> xn--bcher-kva
    except UnicodeError:
        raise _invalid(origin, "host inválido") from None
    if not _HOST_CHARS.match(host):
        raise _invalid(origin, "host inválido")
    return host


def _normalize_origin(origin: str) -> str:
    """Valida a origem e a deixa no formato que o navegador envia no header `Origin`.

    Esquema e host em minúsculas, host internacional em punycode, IP na forma
    canônica, sem barra no fim e sem a porta padrão do esquema. Assim
    `https://App.ts.net:443/` do `.env` casa com o `https://app.ts.net` que o
    navegador manda (a comparação do CORS é exata). Origem que nenhum navegador
    enviaria é recusada na inicialização, em vez de falhar em silêncio depois.
    """
    if origin == "*":
        raise ValueError("'*' não é permitido; liste as origens explicitamente")
    if any(c.isspace() for c in origin):
        raise _invalid(origin)
    parts = urlsplit(origin)
    scheme = parts.scheme  # urlsplit já devolve o esquema em minúsculas
    if (
        scheme not in DEFAULT_PORTS
        or not parts.hostname
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
        or "@" in parts.netloc
        or parts.netloc.endswith(":")
    ):
        raise _invalid(origin)
    host = _canonical_host(origin, parts.hostname)
    try:
        port = parts.port
    except ValueError:
        raise _invalid(origin, "porta inválida") from None
    if port == 0:
        raise _invalid(origin, "porta inválida")
    if port is None or port == DEFAULT_PORTS[scheme]:
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- Aplicação
    app_env: Literal["development", "test", "production"] = "development"

    # --- Banco de dados
    database_url: SecretStr

    # --- JWT (REQ-17/18): par ES256 em PEM, codificado em base64 numa linha
    jwt_private_key_pem_b64: SecretStr
    jwt_public_key_pem_b64: str
    jwt_issuer: str = Field(default="saferdocs", min_length=1)
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
    webauthn_rp_name: str = Field(default="SaferDocs", min_length=1)
    webauthn_origin: str

    # --- Login (REQ-03/05)
    login_max_attempts: int = Field(default=5, gt=0)
    login_lock_minutes: int = Field(default=15, gt=0)
    rate_limit_login_per_ip: str = "10/minute"
    rate_limit_login_per_account: str = "5/minute"
    rate_limit_verify_per_ip: str = "10/minute"

    # --- PDF (REQ-61/62)
    max_upload_mb: int = Field(default=20, gt=0, le=100)
    pdf_worker_socket: str = Field(default="/run/pdf/worker.sock", min_length=1)
    pdf_worker_timeout_seconds: int = Field(default=30, gt=0)

    # --- Cookies (REQ-20)
    cookie_secure: bool = True

    # ------------------------------------------------------------------ validação

    @field_validator("cors_allowed_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    @field_validator("cors_allowed_origins")
    @classmethod
    def _validate_origins(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("informe ao menos uma origem")
        # dict.fromkeys tira as repetidas que só aparecem depois de normalizar, mantendo a ordem.
        return list(dict.fromkeys(_normalize_origin(origin) for origin in value))

    @field_validator("database_url")
    @classmethod
    def _validate_database_url(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value().startswith(("postgresql://", "postgresql+psycopg://")):
            raise ValueError("precisa ser uma URL do PostgreSQL (postgresql+psycopg://...)")
        return value

    @field_validator("master_key", "hash_pepper")
    @classmethod
    def _validate_32_bytes(cls, value: SecretStr) -> SecretStr:
        if len(_decode_b64(value.get_secret_value(), "o valor")) != 32:
            raise ValueError("precisa ser base64 de exatamente 32 bytes")
        return value

    @field_validator("rate_limit_login_per_ip", "rate_limit_login_per_account", "rate_limit_verify_per_ip")
    @classmethod
    def _validate_rate_limit(cls, value: str) -> str:
        if not RATE_LIMIT_PATTERN.match(value):
            raise ValueError("formato esperado: <quantidade>/<second|minute|hour>")
        if int(value.split("/", 1)[0]) < 1:
            raise ValueError("a quantidade precisa ser pelo menos 1")
        return value

    @field_validator("webauthn_rp_id")
    @classmethod
    def _validate_rp_id(cls, value: str) -> str:
        if "://" in value or "/" in value or ":" in value or not value:
            raise ValueError("rpId é só o domínio, sem esquema, porta ou caminho")
        return value

    @field_validator("webauthn_origin")
    @classmethod
    def _validate_webauthn_origin(cls, value: str) -> str:
        return _normalize_origin(value)

    @model_validator(mode="after")
    def _validate_cross_fields(self) -> "Settings":
        self._validate_jwt_keys()
        host = urlsplit(self.webauthn_origin).hostname or ""
        if host != self.webauthn_rp_id and not host.endswith("." + self.webauthn_rp_id):
            raise ValueError("WEBAUTHN_ORIGIN precisa pertencer ao domínio de WEBAUTHN_RP_ID")
        if self.is_production:
            if not self.cookie_secure:
                raise ValueError("COOKIE_SECURE precisa ser true em produção")
            inseguras = [o for o in self.cors_allowed_origins if not o.startswith("https://")]
            if inseguras or not self.webauthn_origin.startswith("https://"):
                raise ValueError("em produção as origens precisam usar https")
        return self

    def _validate_jwt_keys(self) -> None:
        try:
            private = serialization.load_pem_private_key(
                _decode_b64(self.jwt_private_key_pem_b64.get_secret_value(), "a chave"), password=None
            )
            public = serialization.load_pem_public_key(_decode_b64(self.jwt_public_key_pem_b64, "a chave"))
        except ValueError:
            raise ValueError(
                "JWT_PRIVATE_KEY_PEM_B64/JWT_PUBLIC_KEY_PEM_B64 precisam ser PEM válidos em base64"
            ) from None
        if not isinstance(private, ec.EllipticCurvePrivateKey) or not isinstance(private.curve, ec.SECP256R1):
            raise ValueError("a chave do JWT precisa ser ECDSA P-256 (ES256)")
        if private.public_key().public_numbers() != getattr(public, "public_numbers", lambda: None)():
            raise ValueError("JWT_PUBLIC_KEY_PEM_B64 não corresponde à chave privada")

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"


def _format_errors(error: ValidationError) -> str:
    linhas = []
    for item in error.errors(include_input=False, include_url=False, include_context=False):
        campo = ".".join(str(p) for p in item["loc"]).upper() or "configuração"
        mensagem = "variável obrigatória ausente" if item["type"] == "missing" else item["msg"]
        linhas.append(f"  - {campo}: {mensagem.removeprefix('Value error, ')}")
    return "Configuração inválida; a API não vai subir:\n" + "\n".join(linhas)


def load_settings() -> Settings:
    """Lê e valida o ambiente. Lança ConfigError sem expor nenhum valor."""
    try:
        return Settings()  # type: ignore[call-arg]
    except ValidationError as error:
        raise ConfigError(_format_errors(error)) from None


@lru_cache
def get_settings() -> Settings:
    """Settings carregadas e validadas uma única vez por processo."""
    return load_settings()
