"""Logout e revogação de sessões e tokens (REQ-21 e REQ-23)."""

import uuid
from datetime import UTC, datetime

from fastapi import Request, Response
from sqlalchemy import delete, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.api.deps import AuthContext
from app.db.models import JwtDenylist, RefreshToken, UserSession
from app.services import audit_service as audit
from app.services.token_service import clear_refresh_cookie


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


def revoke_sessions(db: Session, session_ids: list[uuid.UUID], reason: str) -> None:
    """Encerra sessões e invalida todos os refresh tokens delas (REQ-23)."""
    if not session_ids:
        return
    now = datetime.now(UTC)
    db.execute(
        update(UserSession)
        .where(UserSession.id.in_(session_ids), UserSession.revoked_at.is_(None))
        .values(revoked_at=now, revoked_reason=reason)
    )
    db.execute(
        update(RefreshToken)
        .where(RefreshToken.session_id.in_(session_ids), RefreshToken.revoked_at.is_(None))
        .values(revoked_at=now)
    )


def logout(db: Session, context: AuthContext, request: Request, response: Response) -> None:
    """Encerra a sessão atual: access token na denylist, refresh token invalidado e cookie apagado."""
    deny_access_token(db, context.claims)
    revoke_sessions(db, [context.session.id], reason="logout")
    clear_refresh_cookie(response)
    audit.record(
        db,
        action=audit.AuditAction.LOGOUT,
        result=audit.AuditResult.SUCCESS,
        request=request,
        user_id=context.user.id,
        details={"session_id": str(context.session.id)},
    )
    db.commit()
