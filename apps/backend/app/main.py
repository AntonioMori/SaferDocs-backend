"""Ponto de entrada da API do SaferDocs.

Monta a aplicação na ordem das camadas descritas no README:
middlewares (entrada) -> rotas /api/v1 -> serviços (domínio) -> infraestrutura.
"""

from fastapi import FastAPI

from app.api.v1.router import api_router


def create_app() -> FastAPI:
    app = FastAPI(
        title="SaferDocs API",
        version="1.0.0",
        docs_url=None,
        redoc_url=None,
        openapi_url="/api/v1/openapi.json",
    )
    app.include_router(api_router)
    return app


app = create_app()
