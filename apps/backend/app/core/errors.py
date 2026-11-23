"""Erros padronizados da API (RNF-12).

Todo erro sai no mesmo formato JSON:

    {"code": "VAL_001", "message": "...", "timestamp": "2026-11-23T14:00:00Z",
     "request_id": "...", "fields": [...]}   # `fields` só em erros de validação

Os serviços lançam `AppError(ErrorCode.X)`; os handlers registrados em
`register_error_handlers` convertem qualquer exceção nesse formato.
"""

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger("saferdocs.errors")


class ErrorCode(StrEnum):
    """Catálogo único de códigos (RNF-13): <DOMÍNIO>_<NNN>.

    Nenhum código de erro é escrito fora daqui. Domínios:
    AUTH (autenticação e sessão), DOC (documentos PDF), VAL (validação de
    entrada), RES (recursos e rotas), RATE (limite de requisições) e SYS
    (erros internos).
    """

    # --- AUTH: autenticação e sessão
    AUTH_INVALID_CREDENTIALS = "AUTH_001"
    AUTH_INVALID_MFA = "AUTH_002"
    AUTH_TOKEN_INVALID = "AUTH_003"  # noqa: S105 (código de erro, não é senha)
    AUTH_TOKEN_REVOKED = "AUTH_004"  # noqa: S105 (código de erro, não é senha)
    AUTH_REFRESH_INVALID = "AUTH_005"
    AUTH_PASSKEY_FAILED = "AUTH_006"
    AUTH_ORIGIN_NOT_ALLOWED = "AUTH_009"
    AUTH_FORBIDDEN = "AUTH_010"

    # --- DOC: documentos PDF
    DOC_NOT_PDF = "DOC_001"
    DOC_TOO_LARGE = "DOC_002"
    DOC_HAS_JAVASCRIPT = "DOC_003"
    DOC_UNPROCESSABLE = "DOC_004"
    DOC_INVALID_POSITION = "DOC_005"

    # --- VAL: validação de entrada
    VALIDATION = "VAL_001"

    # --- RES: recursos e rotas
    NOT_FOUND = "RES_001"
    METHOD_NOT_ALLOWED = "RES_002"

    # --- RATE: limite de requisições
    RATE_LIMITED = "RATE_001"

    # --- SYS: erros internos
    INTERNAL = "SYS_001"

    @property
    def domain(self) -> str:
        return self.value.split("_")[0]


@dataclass(frozen=True)
class ErrorSpec:
    status: int
    message: str


CATALOG: dict[ErrorCode, ErrorSpec] = {
    # AUTH_001 é a mensagem única do REQ-04: não diz se o erro foi no e-mail ou na senha.
    ErrorCode.AUTH_INVALID_CREDENTIALS: ErrorSpec(401, "E-mail ou senha inválidos."),
    ErrorCode.AUTH_INVALID_MFA: ErrorSpec(401, "Código de verificação inválido."),
    ErrorCode.AUTH_TOKEN_INVALID: ErrorSpec(401, "Autenticação necessária."),
    ErrorCode.AUTH_TOKEN_REVOKED: ErrorSpec(401, "Sessão encerrada. Faça login novamente."),
    ErrorCode.AUTH_REFRESH_INVALID: ErrorSpec(401, "Sessão expirada. Faça login novamente."),
    ErrorCode.AUTH_PASSKEY_FAILED: ErrorSpec(400, "Não foi possível validar a passkey."),
    ErrorCode.AUTH_ORIGIN_NOT_ALLOWED: ErrorSpec(403, "Origem da requisição não permitida."),
    ErrorCode.AUTH_FORBIDDEN: ErrorSpec(403, "Você não tem permissão para acessar este recurso."),
    ErrorCode.DOC_NOT_PDF: ErrorSpec(400, "O arquivo enviado não é um PDF."),
    ErrorCode.DOC_TOO_LARGE: ErrorSpec(413, "O arquivo excede o tamanho máximo permitido."),
    ErrorCode.DOC_HAS_JAVASCRIPT: ErrorSpec(400, "PDFs com JavaScript embutido não são aceitos."),
    ErrorCode.DOC_UNPROCESSABLE: ErrorSpec(400, "Não foi possível processar o PDF."),
    ErrorCode.DOC_INVALID_POSITION: ErrorSpec(400, "Página ou posição do selo inválida."),
    ErrorCode.VALIDATION: ErrorSpec(400, "Dados inválidos."),
    ErrorCode.NOT_FOUND: ErrorSpec(404, "Recurso não encontrado."),
    ErrorCode.METHOD_NOT_ALLOWED: ErrorSpec(405, "Método não permitido para este recurso."),
    ErrorCode.RATE_LIMITED: ErrorSpec(429, "Muitas requisições. Aguarde e tente novamente."),
    ErrorCode.INTERNAL: ErrorSpec(500, "Erro interno. Tente novamente mais tarde."),
}


@dataclass(frozen=True)
class FieldError:
    field: str
    reason: str


class AppError(Exception):
    """Erro de negócio com código do catálogo."""

    def __init__(
        self,
        code: ErrorCode,
        message: str | None = None,
        *,
        fields: list[FieldError] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.code = code
        self.spec = CATALOG[code]
        self.message = message or self.spec.message
        self.fields = fields
        self.headers = headers
        super().__init__(f"{code}: {self.message}")


def _timestamp() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def error_response(
    request: Request,
    code: ErrorCode,
    message: str | None = None,
    *,
    fields: list[FieldError] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    spec = CATALOG[code]
    body: dict[str, Any] = {
        "code": str(code),
        "message": message or spec.message,
        "timestamp": _timestamp(),
        "request_id": getattr(request.state, "request_id", None),
    }
    if fields:
        body["fields"] = [{"field": f.field, "reason": f.reason} for f in fields]
    return JSONResponse(status_code=spec.status, content=body, headers=headers)


async def _app_error_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, AppError)
    return error_response(request, exc.code, exc.message, fields=exc.fields, headers=exc.headers)


async def _http_error_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, StarletteHTTPException)
    if exc.status_code == 404:
        return error_response(request, ErrorCode.NOT_FOUND)
    if exc.status_code == 405:
        return error_response(request, ErrorCode.METHOD_NOT_ALLOWED, headers=exc.headers)
    if exc.status_code >= 500:
        return error_response(request, ErrorCode.INTERNAL)
    return error_response(request, ErrorCode.VALIDATION)


_REASONS: dict[str, str] = {
    "missing": "campo obrigatório",
    "json_invalid": "JSON inválido",
    "json_type": "o corpo precisa ser um objeto JSON",
    "model_attributes_type": "o corpo precisa ser um objeto JSON",
    "string_type": "deve ser um texto",
    "int_type": "deve ser um número inteiro",
    "int_parsing": "deve ser um número inteiro",
    "int_from_float": "deve ser um número inteiro",
    "float_type": "deve ser um número",
    "float_parsing": "deve ser um número",
    "bool_type": "deve ser verdadeiro ou falso",
    "bool_parsing": "deve ser verdadeiro ou falso",
    "uuid_type": "identificador inválido",
    "uuid_parsing": "identificador inválido",
    "list_type": "deve ser uma lista",
    "literal_error": "valor não permitido",
    "enum": "valor não permitido",
    "extra_forbidden": "campo não permitido",
    "too_short": "quantidade de itens abaixo do mínimo",
    "too_long": "quantidade de itens acima do máximo",
    "string_pattern_mismatch": "formato inválido",
}


def _reason(err: dict[str, Any]) -> str:
    """Motivo legível da falha, sem repetir o valor enviado (RNF-14)."""
    kind = err["type"]
    ctx = err.get("ctx") or {}
    if kind == "string_too_short":
        return f"mínimo de {ctx.get('min_length')} caracteres"
    if kind == "string_too_long":
        return f"máximo de {ctx.get('max_length')} caracteres"
    if kind in ("greater_than", "greater_than_equal", "less_than", "less_than_equal"):
        simbolos = {
            "greater_than": ">",
            "greater_than_equal": ">=",
            "less_than": "<",
            "less_than_equal": "<=",
        }
        limite = next(iter(ctx.values()), "")
        return f"deve ser {simbolos[kind]} {limite}"
    if kind in ("value_error", "assertion_error"):
        # Mensagens dos nossos próprios validadores, escritas para o usuário.
        return str(ctx.get("error") or err.get("msg", "")).removeprefix("Value error, ") or "valor inválido"
    return _REASONS.get(kind, "valor inválido")


def _field_name(loc: tuple[Any, ...]) -> str:
    # loc vem como ("body", "campo", ...) ou ("query", "nome"); a origem não interessa ao cliente.
    partes = [str(p) for p in loc[1:]] if len(loc) > 1 else [str(p) for p in loc]
    return ".".join(partes)


async def _validation_error_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RequestValidationError)
    fields = [FieldError(_field_name(tuple(err["loc"])), _reason(err)) for err in exc.errors()]
    return error_response(request, ErrorCode.VALIDATION, fields=fields)


async def _unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    # O detalhe fica só no log do servidor; a resposta nunca expõe stack trace.
    logger.exception("Erro não tratado (request_id=%s)", getattr(request.state, "request_id", None))
    return error_response(request, ErrorCode.INTERNAL)


def register_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(AppError, _app_error_handler)
    app.add_exception_handler(StarletteHTTPException, _http_error_handler)
    app.add_exception_handler(RequestValidationError, _validation_error_handler)
    app.add_exception_handler(Exception, _unhandled_error_handler)
