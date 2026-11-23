"""Logout e revogação de tokens (REQ-21 e REQ-23)."""

from datetime import UTC, datetime

from fastapi import Request, Response
from sqlalchemy import delete
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.api.deps import AuthContext
from app.db.models import JwtDenylist
from app.services import audit_service as audit


def deny_access_token(db: Session, claims: dict) -> None:
    """REQ-21: guarda o jti até o fim da validade original do token."""
    expires_at = datetime.fromtimestamp(int(claims["exp"]), tz=UTC)
    db.execute(
        insert(JwtDenylist)
        .values(jti=str(claims["jti"]), expires_at=expires_at)
        .on_conflict_do_nothing(index_elements=["jti"])
    )
    # Entradas vencidas não servem mais: o próprio exp já rejeita esses tokens.
    db.execute(delete(JwtDenylist).where(JwtDenylist.expires_at < datetime.now(UTC)))


def logout(db: Session, context: AuthContext, request: Request, response: Response) -> None:
    del response  # o cookie do refresh é apagado na REQ-23
    deny_access_token(db, context.claims)
    audit.record(
        db,
        action=audit.AuditAction.LOGOUT,
        result=audit.AuditResult.SUCCESS,
        request=request,
        user_id=context.user.id,
        details={"session_id": str(context.session.id)},
    )
    db.commit()
