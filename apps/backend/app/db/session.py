"""Conexão com o PostgreSQL (RNF-04).

Uma `Session` por requisição, entregue pela dependência `get_db`. As rotas
não usam a sessão diretamente: elas a repassam aos serviços.
"""

from collections.abc import Iterator
from functools import lru_cache

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings


@lru_cache
def get_engine() -> Engine:
    settings = get_settings()
    return create_engine(
        settings.database_url.get_secret_value(),
        pool_pre_ping=True,
        # Erro de banco não leva os valores da consulta para o log (hash de senha, e-mail, IP).
        hide_parameters=True,
        pool_size=5,
        max_overflow=10,
    )


@lru_cache
def get_sessionmaker() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), autoflush=False, expire_on_commit=False)


def get_db() -> Iterator[Session]:
    """Dependência do FastAPI: abre uma sessão e garante o fechamento."""
    session = get_sessionmaker()()
    try:
        yield session
    finally:
        session.close()


def check_database() -> None:
    """Executa um `SELECT 1`. Lança exceção se o banco não responder."""
    with get_engine().connect() as connection:
        connection.execute(text("SELECT 1"))
