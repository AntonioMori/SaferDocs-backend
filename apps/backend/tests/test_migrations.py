"""RNF-09: o schema é criado exclusivamente pelas migrations."""

from sqlalchemy import inspect

from alembic import command
from app.db.session import get_engine
from tests.conftest import alembic_config


def _tabelas() -> set[str]:
    return set(inspect(get_engine()).get_table_names())


def test_upgrade_head_cria_o_schema_do_zero(database_available):
    config = alembic_config()
    command.downgrade(config, "base")
    assert "users" not in _tabelas()

    command.upgrade(config, "head")
    tabelas = _tabelas()
    assert "users" in tabelas
    assert "alembic_version" in tabelas


def test_users_tem_as_colunas_dos_dois_lados(migrated_db):
    colunas = {c["name"] for c in inspect(get_engine()).get_columns("users")}
    esperadas = {
        "id",
        "name",
        "email",
        "password_hash",
        "password_changed_at",
        "failed_login_count",
        "locked_until",
        "totp_secret_enc",
        "totp_enabled",
        "totp_last_step",
        "signing_public_key",
        "signing_cert",
        "signing_private_key_enc",
        "created_at",
        "updated_at",
    }
    assert esperadas <= colunas


def test_email_unico_sem_diferenciar_maiusculas(migrated_db):
    indices = {i["name"]: i for i in inspect(get_engine()).get_indexes("users")}
    assert indices["uq_users_email_lower"]["unique"]
