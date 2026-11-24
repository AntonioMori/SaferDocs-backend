"""audit_log imutavel: trigger contra UPDATE, DELETE e TRUNCATE e papel da aplicacao sem essas permissoes

REQ-55. Duas barreiras independentes:
1. Triggers: qualquer UPDATE, DELETE ou TRUNCATE na tabela falha, inclusive
   para o dono da tabela e para superusuários.
2. Permissões: o papel `saferdocs_app` (do qual o usuário de login da API
   deve ser membro em produção) só tem SELECT e INSERT no `audit_log`.

O `ip` passa a ser texto: guarda o valor exatamente como chegou, mesmo
quando não é um endereço válido.

Revision ID: 208d8c8cdcb5
Revises: 05feeddf83b8
Create Date: 2026-11-24 11:04:00.000000+00:00

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "208d8c8cdcb5"
down_revision: str | Sequence[str] | None = "05feeddf83b8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column(
        "audit_log",
        "ip",
        type_=sa.String(length=64),
        existing_type=postgresql.INET(),
        postgresql_using="host(ip)",
    )

    op.execute(
        """
        CREATE FUNCTION audit_log_bloqueia_alteracao() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'audit_log é append-only: % não é permitido', TG_OP
                USING ERRCODE = 'insufficient_privilege';
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_log_sem_update_delete
        BEFORE UPDATE OR DELETE ON audit_log
        FOR EACH ROW EXECUTE FUNCTION audit_log_bloqueia_alteracao()
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_log_sem_truncate
        BEFORE TRUNCATE ON audit_log
        FOR EACH STATEMENT EXECUTE FUNCTION audit_log_bloqueia_alteracao()
        """
    )

    # Papel da aplicação: acesso normal às tabelas, mas só leitura e inserção no audit_log.
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'saferdocs_app') THEN
                CREATE ROLE saferdocs_app NOLOGIN;
            END IF;
        END
        $$
        """
    )
    op.execute("GRANT USAGE ON SCHEMA public TO saferdocs_app")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO saferdocs_app")
    op.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO saferdocs_app")
    op.execute("REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM PUBLIC, saferdocs_app")
    op.execute("GRANT SELECT, INSERT ON audit_log TO saferdocs_app")
    # Tabelas criadas por migrations futuras já nascem acessíveis ao papel.
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO saferdocs_app"
    )
    op.execute("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO saferdocs_app")


def downgrade() -> None:
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE USAGE, SELECT ON SEQUENCES FROM saferdocs_app"
    )
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        "REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM saferdocs_app"
    )
    op.execute("REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM saferdocs_app")
    op.execute("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM saferdocs_app")
    op.execute("REVOKE USAGE ON SCHEMA public FROM saferdocs_app")
    # O papel é do cluster, não do banco: fica, sem nenhuma permissão aqui.

    op.execute("DROP TRIGGER audit_log_sem_truncate ON audit_log")
    op.execute("DROP TRIGGER audit_log_sem_update_delete ON audit_log")
    op.execute("DROP FUNCTION audit_log_bloqueia_alteracao()")

    # Valores que não são endereço válido (ex.: "testclient") viram NULL na volta para INET.
    op.execute(
        """
        CREATE FUNCTION pg_temp.inet_ou_nulo(valor text) RETURNS inet
        LANGUAGE plpgsql AS $$
        BEGIN
            RETURN valor::inet;
        EXCEPTION WHEN others THEN
            RETURN NULL;
        END;
        $$
        """
    )
    op.alter_column(
        "audit_log",
        "ip",
        type_=postgresql.INET(),
        existing_type=sa.String(length=64),
        postgresql_using="pg_temp.inet_ou_nulo(ip)",
    )
