"""Ponto de entrada da API do SaferDocs.

Monta a aplicação na ordem das camadas descritas no README:
middlewares (entrada) -> rotas /api/v1 -> serviços (domínio) -> infraestrutura.
"""

import sys

from fastapi import FastAPI

from app.api.v1.router import api_router
from app.core.config import ConfigError, Settings, get_settings


def _settings_or_exit() -> Settings:
    """RNF-08: sem configuração válida a aplicação se recusa a subir."""
    try:
        return get_settings()
    except ConfigError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from None


def create_app() -> FastAPI:
    settings = _settings_or_exit()
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
