"""CORS (REQ-31 a 36).

Nenhuma origem fora da lista recebe header CORS algum.

- Origem na lista (`CORS_ALLOWED_ORIGINS`): recebe `Access-Control-Allow-Origin`
  com a própria origem, nunca `*` (REQ-31), e `Access-Control-Allow-Credentials:
  true` (REQ-34). O `CORSMiddleware` do Starlette envia esse segundo header até
  para origens fora da lista; por isso esta implementação própria.
- Origem fora da lista: a requisição segue sem nenhum header CORS e o navegador
  bloqueia a leitura da resposta.
- Requisição sem `Origin` (mesma origem, curl, servidores): passa direto.
- Preflight (`OPTIONS` com `Access-Control-Request-Method`): respondida aqui
  mesmo, com 204, antes de rate limit, CSRF e autenticação (REQ-35). A de uma
  origem fora da lista é recusada com 403, sem headers CORS.
"""

from collections.abc import Iterable

from starlette.datastructures import Headers, MutableHeaders
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.errors import ErrorCode, error_response

ALLOWED_METHODS = ("GET", "POST", "PUT", "DELETE", "OPTIONS")
ALLOWED_HEADERS = ("Authorization", "Content-Type", "X-Request-ID")
_ALLOWED_HEADERS_LOWER = frozenset(h.lower() for h in ALLOWED_HEADERS)
# Headers da resposta que o JavaScript da origem permitida pode ler.
EXPOSED_HEADERS = ("X-Request-ID", "Retry-After")
_CORS_RESPONSE_HEADERS = (
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Credentials",
    "Access-Control-Expose-Headers",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Headers",
    "Access-Control-Max-Age",
)


def _add_vary_origin(headers: MutableHeaders) -> None:
    """Acrescenta `Origin` ao `Vary`, preservando o que já existe e sem repetir."""
    present = {v.strip().lower() for v in ",".join(headers.getlist("vary")).split(",")}
    if "origin" not in present and "*" not in present:
        headers.add_vary_header("Origin")


class CORSMiddleware:
    def __init__(self, app: ASGIApp, *, allowed_origins: Iterable[str], max_age: int) -> None:
        self.app = app
        self.allowed_origins = frozenset(allowed_origins)
        self.max_age = max_age

    def is_allowed(self, origin: str) -> bool:
        return origin in self.allowed_origins

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        origins = headers.getlist("origin")
        if not origins:
            # Sem Origin a resposta sai sem headers CORS, mas ainda leva Vary: Origin:
            # a mesma URL responde diferente quando a Origin é permitida.
            await self.app(scope, receive, self._send_with_cors(send, None))
            return
        # Origin tem um único valor. Repetido (proxy que concatena, cliente forjado) conta
        # como origem não confiável, para não validar só a primeira linha.
        origin = origins[0] if len(origins) == 1 else None

        if scope["method"] == "OPTIONS" and "access-control-request-method" in headers:
            response = self._preflight(scope, origin)
            await response(scope, receive, send)
            return

        await self.app(scope, receive, self._send_with_cors(send, origin))

    def _preflight(self, scope: Scope, origin: str | None) -> Response:
        if origin is None or not self.is_allowed(origin):
            return self._reject(scope)
        headers = Headers(scope=scope)
        # REQ-32: só GET, POST, PUT, DELETE e OPTIONS (nomes de método diferenciam maiúsculas).
        # Um único método por preflight: linhas repetidas são recusadas.
        methods = headers.getlist("access-control-request-method")
        if len(methods) != 1 or methods[0].strip() not in ALLOWED_METHODS:
            return self._reject(scope, "Método não permitido para requisições de outra origem.")
        # REQ-33: só Authorization, Content-Type e X-Request-ID (nomes de header não diferenciam).
        # Linhas repetidas valem como uma lista só (RFC 9110, seção 5.3): todas são conferidas.
        requested_raw = ",".join(headers.getlist("access-control-request-headers"))
        requested = {h.strip().lower() for h in requested_raw.split(",")}
        if not (requested - {""}).issubset(_ALLOWED_HEADERS_LOWER):
            return self._reject(scope, "Header não permitido para requisições de outra origem.")
        return Response(
            status_code=204,
            headers={
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Allow-Methods": ", ".join(ALLOWED_METHODS),
                "Access-Control-Allow-Headers": ", ".join(ALLOWED_HEADERS),
                # REQ-36: o navegador guarda esta resposta e não repete a preflight nesse intervalo.
                "Access-Control-Max-Age": str(self.max_age),
                "Vary": "Origin",
            },
        )

    def _reject(self, scope: Scope, message: str | None = None) -> Response:
        """Preflight recusada: erro padronizado, sem nenhum header CORS."""
        response = error_response(Request(scope), ErrorCode.AUTH_ORIGIN_NOT_ALLOWED, message)
        response.headers["Vary"] = "Origin"
        return response

    def _send_with_cors(self, send: Send, origin: str | None) -> Send:
        allowed = origin is not None and self.is_allowed(origin)

        async def wrapped(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                # Só este middleware decide CORS: o que uma rota tenha posto (ex.: `*`) é descartado,
                # para nunca vazar para origem estranha nem para requisição sem Origin.
                for name in _CORS_RESPONSE_HEADERS:
                    del headers[name]
                # A resposta muda conforme a origem: caches não podem reaproveitá-la para outra.
                _add_vary_origin(headers)
                if allowed:
                    headers["Access-Control-Allow-Origin"] = origin
                    # REQ-34: credenciais (cookie de refresh) só para origens confiáveis.
                    headers["Access-Control-Allow-Credentials"] = "true"
                    headers["Access-Control-Expose-Headers"] = ", ".join(EXPOSED_HEADERS)
            await send(message)

        return wrapped
