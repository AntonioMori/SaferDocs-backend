"""Agrega os routers de cada domínio da versão 1 da API (RNF-16).

Todo endpoint é registrado aqui, sob o prefixo `/api/v1`. Uma futura
versão incompatível ganha o próprio pacote (`app/api/v2/`) e um router com
prefixo `/api/v2`, convivendo com esta (ver RNF-17 no README).
"""

from fastapi import APIRouter

from app.api.v1.routes import auth, health, security, sessions

API_V1_PREFIX = "/api/v1"

api_router = APIRouter(prefix=API_V1_PREFIX)
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(sessions.router)
api_router.include_router(security.router)
