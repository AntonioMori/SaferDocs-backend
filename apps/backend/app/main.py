"""Ponto de entrada da API do SaferDocs.

Monta a aplicação na ordem das camadas descritas no README:
middlewares (entrada) -> rotas /api/v1 -> serviços (domínio) -> infraestrutura.
"""

from fastapi import FastAPI

from app.api.v1.router import api_router
from app.core.config import get_settings


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="SaferDocs API",
        version="1.0.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None if settings.is_production else "/api/v1/openapi.json",
    )
    app.include_router(api_router)
    return app


app = create_app()
