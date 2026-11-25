"""Proteção contra CSRF por verificação de Origin/Referer (REQ-65).

O enunciado permite Double Submit Cookie ou a verificação do Origin/Referer.
Usamos a segunda porque o REQ-33 só libera os headers Authorization,
Content-Type e X-Request-ID: não há espaço para um header de token CSRF.

Em todo método que altera estado (POST, PUT, PATCH, DELETE):

1. com `Origin`, ele precisa estar em CORS_ALLOWED_ORIGINS (`null`, repetido
   ou de outro site: 403 ErrorCode.AUTH_ORIGIN_NOT_ALLOWED);
2. sem `Origin`, vale a origem do `Referer`, com a mesma regra;
3. sem nenhum dos dois, a requisição só passa se não trouxer cookie. Um
   cliente de API que usa só o Bearer não manda cookie e não é alvo de CSRF
   (o token não vai sozinho); já um pedido com cookie (o refresh token) e sem
   origem verificável é recusado.

GET, HEAD e OPTIONS não alteram estado e passam direto. A preflight é
respondida antes, pelo CORS.
"""

from collections.abc import Iterable

from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.config import _normalize_origin
from app.core.errors import ErrorCode, error_response

UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _origin_of_referer(referer: str) -> str | None:
    try:
        scheme, _, rest = referer.partition("://")
        host = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        return _normalize_origin(f"{scheme}://{host}")
    except ValueError:
        return None


class CSRFMiddleware:
    def __init__(self, app: ASGIApp, *, allowed_origins: Iterable[str]) -> None:
        self.app = app
        self.allowed_origins = frozenset(allowed_origins)

    def _allowed(self, headers: Headers) -> bool:
        origins = headers.getlist("origin")
        if len(origins) > 1:
            return False
        if origins:
            return origins[0] in self.allowed_origins  # "null" nunca está na lista
        referers = headers.getlist("referer")
        if len(referers) > 1:
            return False
        if referers:
            origin = _origin_of_referer(referers[0])
            return origin is not None and origin in self.allowed_origins
        return "cookie" not in headers

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["method"] in UNSAFE_METHODS:
            if not self._allowed(Headers(scope=scope)):
                response = error_response(Request(scope), ErrorCode.AUTH_ORIGIN_NOT_ALLOWED)
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)
