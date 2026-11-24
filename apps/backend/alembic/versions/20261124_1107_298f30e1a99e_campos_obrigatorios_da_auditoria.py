"""campos obrigatorios da auditoria: ip e user_agent nao nulos e checks de acao, resultado e usuario

REQ-56. Todo registro tem timestamp UTC, IP, User-Agent, ação e resultado.
O usuário só pode faltar em falha de autenticação (e-mail inexistente) e na
verificação pública de documento, que não exige login.

Revision ID: 298f30e1a99e
Revises: 208d8c8cdcb5
Create Date: 2026-11-24 11:07:00.000000+00:00

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "298f30e1a99e"
down_revision: str | Sequence[str] | None = "208d8c8cdcb5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column("audit_log", "ip", existing_type=sa.String(length=64), nullable=False)
    op.alter_column("audit_log", "user_agent", existing_type=sa.Text(), nullable=False)
    op.create_check_constraint("action_preenchida", "audit_log", "action <> ''")
    op.create_check_constraint("result_valido", "audit_log", "result IN ('SUCCESS', 'FAILURE')")
    op.create_check_constraint(
        "user_id_obrigatorio",
        "audit_log",
        "user_id IS NOT NULL OR action IN ('AUTH_FAILURE', 'DOCUMENT_VERIFIED')",
    )


def downgrade() -> None:
    op.drop_constraint("user_id_obrigatorio", "audit_log", type_="check")
    op.drop_constraint("result_valido", "audit_log", type_="check")
    op.drop_constraint("action_preenchida", "audit_log", type_="check")
    op.alter_column("audit_log", "user_agent", existing_type=sa.Text(), nullable=True)
    op.alter_column("audit_log", "ip", existing_type=sa.String(length=64), nullable=True)
