"""Sessões ativas do usuário (REQ-57). Todas as rotas exigem autenticação."""

import uuid

from fastapi import APIRouter, Depends, Request, Response, status

from app.api.deps import CurrentAuth, DbSession, get_auth_context
from app.schemas.sessions import SessionOut
from app.services import session_service

router = APIRouter(prefix="/sessions", tags=["sessions"], dependencies=[Depends(get_auth_context)])


@router.get("", response_model=list[SessionOut])
def list_sessions(context: CurrentAuth, db: DbSession) -> list[SessionOut]:
    """Sessões ativas, com a atual marcada (`current`)."""
    return session_service.list_active_sessions(db, context)


@router.delete("/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_session(
    session_id: uuid.UUID, context: CurrentAuth, request: Request, response: Response, db: DbSession
) -> Response:
    """Encerra uma sessão específica."""
    session_service.revoke_one_session(db, context, session_id, request, response)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.delete("", status_code=status.HTTP_204_NO_CONTENT)
def revoke_all(context: CurrentAuth, request: Request, response: Response, db: DbSession) -> Response:
    """Sair de todos os dispositivos."""
    session_service.revoke_every_session(db, context, request, response)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response
