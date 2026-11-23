"""Alerta de uso do token a partir de outro IP (REQ-26).

Ao contrário do User-Agent (REQ-27), IP diferente não rejeita o token:
redes móveis e VPNs trocam de IP com frequência. O sistema registra o fato
na auditoria e avisa o usuário, uma vez por combinação de sessão e IP novo.
"""

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.request_info import client_ip
from app.crypto.keyed_hash import keyed_hash
from app.db.models import SecurityEvent, UserSession
from app.services import audit_service as audit
from app.services import security_events
from app.services.security_events import SecurityEventType


def check_ip(db: Session, session: UserSession, claim_ip_hash: str, request: Request) -> bool:
    """Compara o IP atual com o do login. Retorna True se mudou (e alerta uma única vez)."""
    current = keyed_hash(client_ip(request) or "")
    if current == claim_ip_hash:
        return False

    already = db.scalar(
        select(SecurityEvent.id).where(
            SecurityEvent.user_id == session.user_id,
            SecurityEvent.type == SecurityEventType.IP_CHANGED,
            SecurityEvent.details["session_id"].astext == str(session.id),
            SecurityEvent.details["ip_hmac"].astext == current,
        )
    )
    if already is None:
        details = {"session_id": str(session.id), "ip_hmac": current}
        audit.record(
            db,
            action=audit.AuditAction.IP_MISMATCH,
            result=audit.AuditResult.SUCCESS,
            request=request,
            user_id=session.user_id,
            details=details,
        )
        security_events.emit(
            db, user_id=session.user_id, type=SecurityEventType.IP_CHANGED, request=request, details=details
        )
        db.commit()
    return True
