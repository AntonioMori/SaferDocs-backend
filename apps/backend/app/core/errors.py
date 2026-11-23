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
    VALIDATION = "VAL_001"
    NOT_FOUND = "RES_001"
    METHOD_NOT_ALLOWED = "RES_002"
    INTERNAL = "SYS_001"


@dataclass(frozen=True)
class ErrorSpec:
    status: int
    message: str


CATALOG: dict[ErrorCode, ErrorSpec] = {
    ErrorCode.VALIDATION: ErrorSpec(400, "Dados inválidos."),
    ErrorCode.NOT_FOUND: ErrorSpec(404, "Recurso não encontrado."),
    ErrorCode.METHOD_NOT_ALLOWED: ErrorSpec(405, "Método não permitido para este recurso."),
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


async def _validation_error_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RequestValidationError)
    fields = [
        FieldError(".".join(str(p) for p in err["loc"][1:]) or str(err["loc"][0]), "valor inválido")
        for err in exc.errors()
    ]
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
