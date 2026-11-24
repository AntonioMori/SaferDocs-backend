"""Cabeçalhos de segurança HTTP (REQ-37 a 44).

Aplicados a toda resposta da API, inclusive erros, preflights e rotas
inexistentes. Os valores são os recomendados no enunciado e ficam fixos aqui
(não vêm do `.env`): nenhuma configuração de ambiente consegue enfraquecê-los.

A CSP da página do frontend é servida pelo nginx/Vite junto com o HTML; esta
vale para as respostas da própria API.
"""

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

SECURITY_HEADERS: dict[str, str] = {
    # REQ-37: só recursos da própria origem, nenhum plugin (<object>/<embed>) e nada de <iframe>.
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'"
    ),
    # REQ-38: força HTTPS por 2 anos, também nos subdomínios, sem rebaixamento para HTTP.
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
}


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS.items():
                    headers[name] = value
            await send(message)

        await self.app(scope, receive, send_with_headers)
