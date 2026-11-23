"""Identificador de requisição (header X-Request-ID).

Usa o valor enviado pelo cliente se for seguro; caso contrário, gera um
UUID. O id vai para `request.state.request_id`, para as respostas de erro e
para o header da resposta, facilitando rastrear uma falha nos logs.
"""

import re
import uuid

from starlette.types import ASGIApp, Message, Receive, Scope, Send

HEADER = "x-request-id"
SAFE_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class RequestIdMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        received = next((v.decode("latin-1") for k, v in scope["headers"] if k == HEADER.encode()), "")
        request_id = received if SAFE_ID.match(received) else str(uuid.uuid4())
        scope.setdefault("state", {})["request_id"] = request_id

        async def send_with_id(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = [(k, v) for k, v in message.get("headers", []) if k != HEADER.encode()]
                headers.append((HEADER.encode(), request_id.encode()))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_id)
