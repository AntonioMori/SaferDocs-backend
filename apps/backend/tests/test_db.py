"""RNF-04: a API conecta no PostgreSQL."""

from fastapi.testclient import TestClient
from sqlalchemy import text

from app.db.session import get_db
from app.main import app


def test_conecta_no_postgres(database_available):
    session = next(get_db())
    versao = session.execute(text("SHOW server_version")).scalar_one()
    assert versao.split(".")[0].isdigit()
    session.close()


def test_api_sobe_conectando_no_banco(database_available):
    # O `with` executa o lifespan, que verifica o banco antes de atender.
    with TestClient(app) as client:
        assert client.get("/api/v1/health").status_code == 200
