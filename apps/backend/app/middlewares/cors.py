"""CORS (REQ-31 a 36).

Implementação própria, em vez do `CORSMiddleware` do Starlette, para que
nenhuma origem fora da lista receba header CORS algum.

- Origem na lista (`CORS_ALLOWED_ORIGINS`): recebe `Access-Control-Allow-Origin`
  com a própria origem, nunca `*` (REQ-31).
- Origem fora da lista: a requisição segue sem nenhum header CORS e o navegador
  bloqueia a leitura da resposta.
- Requisição sem `Origin` (mesma origem, curl, servidores): passa direto.
"""

from collections.abc import Iterable

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class CORSMiddleware:
    def __init__(self, app: ASGIApp, *, allowed_origins: Iterable[str]) -> None:
        self.app = app
        self.allowed_origins = frozenset(allowed_origins)

    def is_allowed(self, origin: str) -> bool:
        return origin in self.allowed_origins

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        origin = Headers(scope=scope).get("origin")
        if origin is None:
            await self.app(scope, receive, send)
            return

        await self.app(scope, receive, self._send_with_cors(send, origin))

    def _send_with_cors(self, send: Send, origin: str) -> Send:
        allowed = self.is_allowed(origin)

        async def wrapped(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                # A resposta muda conforme a origem: caches não podem reaproveitá-la para outra.
                headers.add_vary_header("Origin")
                if allowed:
                    headers["Access-Control-Allow-Origin"] = origin
            await send(message)

        return wrapped
