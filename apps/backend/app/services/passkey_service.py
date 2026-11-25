"""Passkeys (REQ-06 a 10): cerimônias WebAuthn de registro e de autenticação.

    registro:     /auth/passkeys/register/options -> navigator.credentials.create -> /register/verify
    autenticação: /auth/passkeys/login/options    -> navigator.credentials.get    -> /login/verify

O desafio é aleatório (32 bytes), guardado no banco, de uso único e válido por
5 minutos. Na volta, o desafio é lido do clientDataJSON e procurado no banco;
a biblioteca (py_webauthn) confere assinatura, desafio, origem e rpId.

A passkey dispensa senha e TOTP (já é um fator forte, com verificação do
usuário exigida) e termina no mesmo `_complete_login` do login com senha:
sessão, tokens, auditoria e aviso de IP novo.
"""

import base64
import json
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.exceptions import InvalidAuthenticationResponse, InvalidRegistrationResponse
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from app.core.config import get_settings
from app.core.errors import AppError, ErrorCode
from app.db.models import User, WebauthnChallenge, WebauthnCredential
from app.schemas.auth import TokenOut
from app.services import audit_service as audit
from app.services.auth_service import _complete_login

CHALLENGE_BYTES = 32
CHALLENGE_TTL = timedelta(minutes=5)
CEREMONY_TIMEOUT_MS = 120_000
DEFAULT_PASSKEY_NAME = "Passkey"
MAX_CREDENTIALS_PER_USER = 20

KIND_REGISTER = "register"
KIND_LOGIN = "login"


def _now() -> datetime:
    return datetime.now(UTC)


def _fail(db: Session, request: Request, user_id: uuid.UUID | None, reason: str) -> AppError:
    """Falha de cerimônia: vai para a auditoria e vira ErrorCode.AUTH_PASSKEY_FAILED, sem dizer o motivo ao cliente."""
    db.rollback()
    audit.record(
        db,
        action=audit.AuditAction.AUTH_FAILURE,
        result=audit.AuditResult.FAILURE,
        request=request,
        user_id=user_id,
        details={"method": "passkey", "reason": reason},
    )
    db.commit()
    return AppError(ErrorCode.AUTH_PASSKEY_FAILED)


def _new_challenge(db: Session, kind: str, user_id: uuid.UUID | None) -> bytes:
    challenge = secrets.token_bytes(CHALLENGE_BYTES)
    db.add(
        WebauthnChallenge(user_id=user_id, challenge=challenge, kind=kind, expires_at=_now() + CHALLENGE_TTL)
    )
    return challenge


def _challenge_from_client_data(credential: dict[str, Any]) -> bytes | None:
    """Desafio que o navegador assinou, lido do clientDataJSON (base64url)."""
    try:
        raw = credential["response"]["clientDataJSON"]
        client_data = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
        value = client_data["challenge"]
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (KeyError, TypeError, ValueError):
        return None


def _consume_challenge(
    db: Session, challenge: bytes | None, kind: str, user_id: uuid.UUID | None
) -> bytes | None:
    """Marca o desafio como usado (uso único). Devolve None se ele não existe, expirou ou já foi usado."""
    if not challenge:
        return None
    row = db.scalar(
        select(WebauthnChallenge)
        .where(WebauthnChallenge.challenge == challenge, WebauthnChallenge.kind == kind)
        .with_for_update()
    )
    if row is None or row.used_at is not None or row.expires_at <= _now():
        return None
    if user_id is not None and row.user_id != user_id:
        return None
    row.used_at = _now()
    value = row.challenge
    # Commit já: o desafio fica queimado mesmo que a verificação a seguir falhe (e desfaça a transação).
    db.commit()
    return value


# --------------------------------------------------------------- registro


def registration_options(db: Session, user: User) -> dict[str, Any]:
    """Opções do navigator.credentials.create para o usuário autenticado."""
    settings = get_settings()
    existing = db.scalars(
        select(WebauthnCredential.credential_id).where(WebauthnCredential.user_id == user.id)
    )
    challenge = _new_challenge(db, KIND_REGISTER, user.id)
    options = generate_registration_options(
        rp_id=settings.webauthn_rp_id,
        rp_name=settings.webauthn_rp_name,
        user_id=user.id.bytes,
        user_name=user.email,
        user_display_name=user.name,
        challenge=challenge,
        timeout=CEREMONY_TIMEOUT_MS,
        # Passkey de verdade: credencial descobrível (login sem digitar e-mail) e biometria/PIN.
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        # Não deixa cadastrar duas vezes o mesmo autenticador.
        exclude_credentials=[PublicKeyCredentialDescriptor(id=cred_id) for cred_id in existing],
    )
    db.commit()
    return json.loads(options_to_json(options))


def register_credential(
    db: Session, user: User, credential: dict[str, Any], request: Request, name: str | None = None
) -> WebauthnCredential:
    """Confere a resposta do navigator.credentials.create e guarda o dispositivo."""
    settings = get_settings()
    challenge = _consume_challenge(db, _challenge_from_client_data(credential), KIND_REGISTER, user.id)
    if challenge is None:
        raise _fail(db, request, user.id, "challenge")
    try:
        verified = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=settings.webauthn_rp_id,
            expected_origin=settings.webauthn_origin,
            require_user_verification=True,
        )
    except (InvalidRegistrationResponse, ValueError, TypeError, KeyError):
        raise _fail(db, request, user.id, "registration") from None
    if db.scalar(
        select(WebauthnCredential.id).where(WebauthnCredential.credential_id == verified.credential_id)
    ):
        raise _fail(db, request, user.id, "duplicate")
    count = len(db.scalars(select(WebauthnCredential.id).where(WebauthnCredential.user_id == user.id)).all())
    if count >= MAX_CREDENTIALS_PER_USER:
        raise _fail(db, request, user.id, "limit")
    transports = credential.get("response", {}).get("transports")
    stored = WebauthnCredential(
        user_id=user.id,
        credential_id=verified.credential_id,
        public_key=verified.credential_public_key,
        counter=verified.sign_count,
        aaguid=uuid.UUID(verified.aaguid),
        name=name or DEFAULT_PASSKEY_NAME,
        transports=[str(t)[:20] for t in transports][:8] if isinstance(transports, list) else None,
    )
    db.add(stored)
    audit.record(
        db,
        action=audit.AuditAction.PASSKEY_REGISTERED,
        result=audit.AuditResult.SUCCESS,
        request=request,
        user_id=user.id,
    )
    db.commit()
    db.refresh(stored)
    return stored


# --------------------------------------------------------------- autenticação


def authentication_options(db: Session) -> dict[str, Any]:
    """Opções do navigator.credentials.get. Sem e-mail: a credencial descobrível diz quem é."""
    settings = get_settings()
    challenge = _new_challenge(db, KIND_LOGIN, None)
    options = generate_authentication_options(
        rp_id=settings.webauthn_rp_id,
        challenge=challenge,
        timeout=CEREMONY_TIMEOUT_MS,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    db.commit()
    return json.loads(options_to_json(options))


def _credential_raw_id(credential: dict[str, Any]) -> bytes | None:
    try:
        raw = credential["rawId"]
        return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    except (KeyError, TypeError, ValueError):
        return None


def authenticate(db: Session, credential: dict[str, Any], request: Request, response: Response) -> TokenOut:
    """Confere a resposta do navigator.credentials.get e faz o login (mesmo fim do login com senha)."""
    settings = get_settings()
    challenge = _consume_challenge(db, _challenge_from_client_data(credential), KIND_LOGIN, None)
    if challenge is None:
        raise _fail(db, request, None, "challenge")
    raw_id = _credential_raw_id(credential)
    stored = (
        db.scalar(
            select(WebauthnCredential).where(WebauthnCredential.credential_id == raw_id).with_for_update()
        )
        if raw_id
        else None
    )
    if stored is None:
        raise _fail(db, request, None, "unknown_credential")
    try:
        verified = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=settings.webauthn_rp_id,
            expected_origin=settings.webauthn_origin,
            credential_public_key=stored.public_key,
            credential_current_sign_count=stored.counter,
            require_user_verification=True,
        )
    except (InvalidAuthenticationResponse, ValueError, TypeError, KeyError):
        raise _fail(db, request, stored.user_id, "assertion") from None
    stored.counter = verified.new_sign_count
    user = db.get(User, stored.user_id)
    if user is None:
        raise _fail(db, request, None, "unknown_user")
    return _complete_login(db, user, request, response)
