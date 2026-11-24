"""Leitura do upload de PDF (REQ-61), em streaming e só em memória.

O `UploadFile` do FastAPI grava em arquivo temporário todo upload acima de
1 MB e só entrega o controle à rota depois de ler o corpo inteiro. Aqui o
`multipart/form-data` é lido pedaço a pedaço, direto da conexão:

- **Tamanho (REQ-61):** `Content-Length` acima do limite é recusado sem ler
  nada; sem ele (ou com ele mentindo), a leitura para no primeiro byte que
  passar do limite. Os dois casos dão 413 (`ErrorCode.DOC_TOO_LARGE`).
- **Sem disco (seção 9.2 do enunciado):** o PDF fica num `bytearray` e nunca
  vai para arquivo, banco ou log.
- **Formato fechado:** um único arquivo no campo `file` e só os campos de texto
  que a rota declarar, cada um curto e uma vez só.

Uso numa rota:

    async def assinar(upload: Annotated[PdfUpload, Depends(pdf_upload_with("page", "x", "y"))]): ...
"""

from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from typing import Any

from fastapi import Request
from python_multipart.multipart import MultipartParseError, MultipartParser, parse_options_header

from app.core.config import get_settings
from app.core.errors import AppError, ErrorCode, FieldError

FILE_FIELD = "file"
MAX_TEXT_FIELD_BYTES = 256
# Folga para boundaries, cabeçalhos das partes e campos de texto além do arquivo.
MULTIPART_OVERHEAD_BYTES = 64 * 1024


@dataclass(frozen=True)
class PdfUpload:
    pdf: bytes
    fields: dict[str, str] = field(default_factory=dict)


def _invalid(field_name: str, reason: str) -> AppError:
    return AppError(ErrorCode.VALIDATION, fields=[FieldError(field_name, reason)])


def _too_large() -> AppError:
    return AppError(ErrorCode.DOC_TOO_LARGE)


class _Collector:
    """Recebe os callbacks do parser e monta o arquivo e os campos, com limites."""

    def __init__(self, *, max_file_bytes: int, text_fields: frozenset[str]) -> None:
        self.max_file_bytes = max_file_bytes
        self.text_fields = text_fields
        self.pdf: bytearray | None = None
        self.fields: dict[str, str] = {}
        self.ended = False
        self._header_field = bytearray()
        self._header_value = bytearray()
        self._headers: dict[bytes, bytes] = {}
        self._name: str | None = None
        self._is_file = False
        self._buffer = bytearray()

    # --- cabeçalhos de cada parte
    def on_part_begin(self) -> None:
        self._headers = {}
        self._name = None
        self._is_file = False
        self._buffer = bytearray()

    def on_header_field(self, data: bytes, start: int, end: int) -> None:
        self._header_field += data[start:end]

    def on_header_value(self, data: bytes, start: int, end: int) -> None:
        self._header_value += data[start:end]

    def on_header_end(self) -> None:
        self._headers[bytes(self._header_field).lower()] = bytes(self._header_value)
        self._header_field = bytearray()
        self._header_value = bytearray()

    def on_headers_finished(self) -> None:
        disposition, params = parse_options_header(self._headers.get(b"content-disposition", b""))
        if disposition != b"form-data" or b"name" not in params:
            raise _invalid(FILE_FIELD, "envio inválido")
        try:
            name = params[b"name"].decode("utf-8")
        except UnicodeDecodeError:
            raise _invalid(FILE_FIELD, "envio inválido") from None
        if name == FILE_FIELD:
            if self.pdf is not None:
                raise _invalid(FILE_FIELD, "envie um único arquivo")
            self.pdf = bytearray()
            self._is_file = True
        elif name in self.text_fields:
            if name in self.fields:
                raise _invalid(name, "campo repetido")
        else:
            raise _invalid(name, "campo não permitido")
        self._name = name

    # --- conteúdo
    def on_part_data(self, data: bytes, start: int, end: int) -> None:
        chunk = data[start:end]
        if self._is_file:
            assert self.pdf is not None
            if len(self.pdf) + len(chunk) > self.max_file_bytes:
                raise _too_large()  # REQ-61: para no primeiro byte acima do limite
            self.pdf += chunk
        else:
            if len(self._buffer) + len(chunk) > MAX_TEXT_FIELD_BYTES:
                raise _invalid(self._name or FILE_FIELD, f"máximo de {MAX_TEXT_FIELD_BYTES} bytes")
            self._buffer += chunk

    def on_part_end(self) -> None:
        if not self._is_file and self._name is not None:
            try:
                self.fields[self._name] = self._buffer.decode("utf-8")
            except UnicodeDecodeError:
                raise _invalid(self._name, "texto inválido") from None

    def on_end(self) -> None:
        self.ended = True

    def callbacks(self) -> dict[str, Callable[..., None]]:
        return {
            "on_part_begin": self.on_part_begin,
            "on_header_field": self.on_header_field,
            "on_header_value": self.on_header_value,
            "on_header_end": self.on_header_end,
            "on_headers_finished": self.on_headers_finished,
            "on_part_data": self.on_part_data,
            "on_part_end": self.on_part_end,
            "on_end": self.on_end,
        }


async def read_pdf_upload(
    request: Request, *, max_file_bytes: int, text_fields: frozenset[str] = frozenset()
) -> PdfUpload:
    """Lê o `multipart/form-data` da requisição em memória, respeitando os limites."""
    content_type, params = parse_options_header(request.headers.get("content-type"))
    boundary = params.get(b"boundary")
    if content_type != b"multipart/form-data" or not boundary:
        raise _invalid(FILE_FIELD, "envie o arquivo como multipart/form-data")

    max_body_bytes = max_file_bytes + MULTIPART_OVERHEAD_BYTES
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > max_body_bytes:
        raise _too_large()  # nem começa a ler

    collector = _Collector(max_file_bytes=max_file_bytes, text_fields=text_fields)
    parser = MultipartParser(boundary, collector.callbacks())  # type: ignore[arg-type]
    received = 0
    try:
        async for chunk in request.stream():
            received += len(chunk)
            if received > max_body_bytes:
                raise _too_large()  # Content-Length ausente ou falso: para no limite
            parser.write(chunk)
        parser.finalize()
    except MultipartParseError:
        raise _invalid(FILE_FIELD, "envio inválido") from None

    if not collector.ended:
        raise _invalid(FILE_FIELD, "envio incompleto")
    if collector.pdf is None:
        raise _invalid(FILE_FIELD, "campo obrigatório")
    missing = sorted(text_fields - collector.fields.keys())
    if missing:
        raise AppError(
            ErrorCode.VALIDATION, fields=[FieldError(name, "campo obrigatório") for name in missing]
        )
    return PdfUpload(pdf=bytes(collector.pdf), fields=collector.fields)


def pdf_upload_with(*text_fields: str) -> Callable[[Request], Coroutine[Any, Any, PdfUpload]]:
    """Dependência do FastAPI: o PDF do campo `file` e os campos de texto pedidos."""
    allowed = frozenset(text_fields)

    async def dependency(request: Request) -> PdfUpload:
        max_file_bytes = get_settings().max_upload_mb * 1024 * 1024
        return await read_pdf_upload(request, max_file_bytes=max_file_bytes, text_fields=allowed)

    return dependency
