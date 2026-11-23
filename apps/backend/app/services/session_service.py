"""Refresh, logout, troca de senha e revogação de sessões e tokens (REQ-21, 23, 25 e 29)."""

import uuid
from datetime import UTC, datetime

from fastapi import Request, Response
from sqlalchemy import delete, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.api.deps import AuthContext
from app.core.errors import AppError, ErrorCode, FieldError
from app.crypto.passwords import hash_password, verify_password
from app.db.models import JwtDenylist, RefreshToken, UserSession
from app.schemas.auth import ChangePasswordIn, TokenOut, UserOut
from app.services import audit_service as audit
from app.services import security_events
from app.services.security_events import SecurityEventType
from app.services.token_service import clear_refresh_cookie, issue_tokens, rotate_refresh_token


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


def change_password(
    db: Session, context: AuthContext, data: ChangePasswordIn, request: Request, response: Response
) -> TokenOut:
    """Troca a senha, derruba todas as sessões anteriores e abre uma nova (REQ-25).

    `password_changed_at` é truncado no segundo, a mesma resolução do claim `iat`:
    tokens emitidos antes dele passam a ser rejeitados, e o par novo, emitido
    em seguida, continua válido.
    """
    user = context.user
    if not verify_password(user.password_hash, data.current_password):
        raise AppError(ErrorCode.VALIDATION, fields=[FieldError("current_password", "senha atual incorreta")])
    if verify_password(user.password_hash, data.new_password):
        raise AppError(
            ErrorCode.VALIDATION, fields=[FieldError("new_password", "precisa ser diferente da senha atual")]
        )

    user.password_hash = hash_password(data.new_password)
    user.password_changed_at = datetime.now(UTC).replace(microsecond=0)
    ativas = db.scalars(
        select(UserSession.id).where(UserSession.user_id == user.id, UserSession.revoked_at.is_(None))
    ).all()
    revoke_sessions(db, list(ativas), reason="password_changed")
    deny_access_token(db, context.claims)

    audit.record(
        db,
        action=audit.AuditAction.PASSWORD_CHANGED,
        result=audit.AuditResult.SUCCESS,
        request=request,
        user_id=user.id,
    )
    security_events.emit(db, user_id=user.id, type=SecurityEventType.PASSWORD_CHANGED, request=request)
    tokens = issue_tokens(db, user, request, response)
    db.commit()
    return TokenOut(
        access_token=tokens.access_token,
        token_type=tokens.token_type,
        expires_in=tokens.expires_in,
        user=UserOut.model_validate(user),
    )


def refresh(db: Session, request: Request, response: Response) -> TokenOut:
    """Rotação do refresh token (REQ-29): emite um par novo na mesma sessão."""
    user, tokens = rotate_refresh_token(db, request, response)
    for action in (audit.AuditAction.TOKEN_REFRESHED, audit.AuditAction.TOKEN_ISSUED):
        audit.record(db, action=action, result=audit.AuditResult.SUCCESS, request=request, user_id=user.id)
    db.commit()
    return TokenOut(
        access_token=tokens.access_token,
        token_type=tokens.token_type,
        expires_in=tokens.expires_in,
        user=UserOut.model_validate(user),
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
