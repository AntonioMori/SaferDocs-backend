"""RNF-10: toda mudança de schema passa por uma migration.

Equivale ao `alembic check`: aplica as migrations num banco limpo e compara
o resultado com os models. Se alguém alterar um model sem criar a migration
(ou criar uma tabela à mão), o teste falha.
"""

from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext

from app.db import models  # noqa: F401  (registra as tabelas)
from app.db.base import Base
from app.db.session import get_engine


def test_models_e_migrations_estao_sincronizados(migrated_db):
    with get_engine().connect() as connection:
        contexto = MigrationContext.configure(connection, opts={"compare_type": True})
        diferencas = compare_metadata(contexto, Base.metadata)
    assert diferencas == [], (
        "Models e migrations divergem. Gere a migration com:\n"
        '  uv run alembic revision --autogenerate -m "descrição"\n'
        f"Diferenças: {diferencas}"
    )
