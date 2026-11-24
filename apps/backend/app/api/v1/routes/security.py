"""Atividade de segurança da conta (REQ-58). Todas as rotas exigem autenticação."""

from fastapi import APIRouter, Depends, Response, status

from app.api.deps import CurrentUser, DbSession, get_current_user
from app.schemas.security import MarkSeenIn, SecurityEventOut
from app.services import security_events

router = APIRouter(prefix="/security", tags=["security"], dependencies=[Depends(get_current_user)])


@router.get("/events", response_model=list[SecurityEventOut])
def list_events(user: CurrentUser, db: DbSession) -> list[SecurityEventOut]:
    """Eventos de segurança da conta, os não vistos primeiro."""
    return [
        SecurityEventOut(
            id=e.id, type=e.type, created_at=e.created_at, seen=e.seen_at is not None, details=e.details
        )
        for e in security_events.list_events(db, user.id)
    ]


@router.post("/events/seen", status_code=status.HTTP_204_NO_CONTENT)
def mark_seen(data: MarkSeenIn, user: CurrentUser, db: DbSession) -> Response:
    """Marca eventos como vistos. Ids de outro usuário são ignorados."""
    security_events.mark_seen(db, user.id, data.ids)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
