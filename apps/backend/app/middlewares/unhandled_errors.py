"""Erro 500 dentro da cadeia de middlewares.

O handler de `Exception` do FastAPI roda no `ServerErrorMiddleware`, que fica
por fora de todos os middlewares da aplicação. A resposta 500 sairia sem os
headers de segurança (REQ-37 a 44), sem CORS e sem `X-Request-ID`.

Este middleware é o mais interno: captura a exceção não tratada e devolve o
erro padronizado `ErrorCode.INTERNAL` por dentro da cadeia, então o 500 passa por CORS,
security headers e request_id como qualquer outra resposta. O detalhe da
exceção fica só no log do servidor.
"""

import logging

from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.errors import ErrorCode, error_response

logger = logging.getLogger("saferdocs.errors")


class UnhandledErrorMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        started = False

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, receive, tracking_send)
        except Exception:
            if started:
                # Parte da resposta já saiu: não dá para trocar por um 500.
                raise
            request = Request(scope)
            logger.exception("Erro não tratado (request_id=%s)", getattr(request.state, "request_id", None))
            await error_response(request, ErrorCode.INTERNAL)(scope, receive, send)
