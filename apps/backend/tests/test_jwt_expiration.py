"""REQ-18: o access token expira em 15 minutos."""

import base64
import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from fastapi import APIRouter
from fastapi.testclient import TestClient

from app.api.deps import CurrentUser
from app.core.config import get_settings
from app.crypto.jwt import ALGORITHM, decode_access_token, encode_access_token
from app.crypto.keyed_hash import keyed_hash
from app.db.models import User, UserSession
from app.db.session import get_sessionmaker
from app.main import create_app
from tests.conftest import TEST_ENV


def _token_emitido_em(momento: datetime, subject: uuid.UUID, session_id: uuid.UUID | None = None) -> str:
    claims = {
        "iss": get_settings().jwt_issuer,
        "sub": str(subject),
        "iat": int(momento.timestamp()),
        "exp": int((momento + timedelta(seconds=900)).timestamp()),
        "jti": str(uuid.uuid4()),
        "session_id": str(session_id or uuid.uuid4()),
    }
    return jwt.encode(claims, base64.b64decode(TEST_ENV["JWT_PRIVATE_KEY_PEM_B64"]), algorithm=ALGORITHM)


def test_validade_padrao_e_de_15_minutos():
    assert get_settings().access_token_ttl_seconds == 900
    _, claims = encode_access_token(uuid.uuid4())
    assert claims["exp"] - claims["iat"] == 900


def test_token_ainda_dentro_dos_15_minutos_e_aceito():
    token = _token_emitido_em(datetime.now(UTC) - timedelta(minutes=14), uuid.uuid4())
    assert decode_access_token(token)


def test_token_com_mais_de_15_minutos_e_rejeitado():
    token = _token_emitido_em(datetime.now(UTC) - timedelta(minutes=16), uuid.uuid4())
    with pytest.raises(jwt.ExpiredSignatureError):
        decode_access_token(token)


def test_api_responde_401_para_token_expirado(migrated_db):
    router = APIRouter()

    @router.get("/api/v1/_teste/eu")
    def _eu(user: CurrentUser):
        return {"id": str(user.id)}

    app = create_app()
    app.include_router(router)
    with get_sessionmaker()() as db:
        user = User(name="Ana", email=f"exp-{uuid.uuid4().hex[:8]}@teste.dev", password_hash="!")
        db.add(user)
        db.flush()
        sessao = UserSession(
            user_id=user.id, ip_hmac=keyed_hash("testclient"), ua_hmac=keyed_hash("testclient")
        )
        db.add(sessao)
        db.commit()
        user_id, session_id = user.id, sessao.id

    client = TestClient(app)
    expirado = _token_emitido_em(datetime.now(UTC) - timedelta(minutes=16), user_id, session_id)
    resposta = client.get("/api/v1/_teste/eu", headers={"Authorization": f"Bearer {expirado}"})
    assert resposta.status_code == 401
    assert resposta.json()["code"] == "AUTH_003"

    valido = _token_emitido_em(datetime.now(UTC), user_id, session_id)
    assert client.get("/api/v1/_teste/eu", headers={"Authorization": f"Bearer {valido}"}).status_code == 200
