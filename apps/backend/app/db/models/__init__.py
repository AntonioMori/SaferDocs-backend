"""Models do banco. Importar este pacote registra todas as tabelas no metadata."""

from app.db.models.audit import AuditLog, KnownIp, SecurityEvent
from app.db.models.auth import MfaChallenge, RecoveryCode
from app.db.models.session import JwtDenylist, RefreshToken, UserSession
from app.db.models.signature import Signature
from app.db.models.user import User
from app.db.models.webauthn import WebauthnChallenge, WebauthnCredential

__all__ = [
    "AuditLog",
    "JwtDenylist",
    "KnownIp",
    "MfaChallenge",
    "RecoveryCode",
    "RefreshToken",
    "SecurityEvent",
    "Signature",
    "User",
    "UserSession",
    "WebauthnChallenge",
    "WebauthnCredential",
]
