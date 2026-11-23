"""Ponto de entrada da API do SaferDocs.

Monta a aplicação na ordem das camadas descritas no README:
middlewares (entrada) -> rotas /api/v1 -> serviços (domínio) -> infraestrutura.
"""

import logging
import sys
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy.exc import OperationalError

from app.api.v1.router import api_router
from app.core.config import ConfigError, Settings, get_settings
from app.db.session import check_database

logger = logging.getLogger("saferdocs")

DB_STARTUP_ATTEMPTS = 10
DB_STARTUP_DELAY_SECONDS = 1.5


def _settings_or_exit() -> Settings:
    """RNF-08: sem configuração válida a aplicação se recusa a subir."""
    try:
        return get_settings()
    except ConfigError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from None


def _wait_for_database() -> None:
    """RNF-04: a API só começa a atender depois de conectar no PostgreSQL."""
    for attempt in range(1, DB_STARTUP_ATTEMPTS + 1):
        try:
            check_database()
            logger.info("Conectado ao PostgreSQL")
            return
        except OperationalError:
            logger.warning("PostgreSQL indisponível (tentativa %d/%d)", attempt, DB_STARTUP_ATTEMPTS)
            time.sleep(DB_STARTUP_DELAY_SECONDS)
    print("Não foi possível conectar ao PostgreSQL; a API não vai subir.", file=sys.stderr)
    raise SystemExit(1)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    _wait_for_database()
    yield


def create_app() -> FastAPI:
    settings = _settings_or_exit()
    app = FastAPI(
        title="SaferDocs API",
        version="1.0.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None if settings.is_production else "/api/v1/openapi.json",
        lifespan=lifespan,
    )
    app.include_router(api_router)
    return app


app = create_app()
