"""REQ-24: todo access token tem um jti único (usado pela denylist)."""

import base64
import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app.crypto.jwt import ALGORITHM, decode_access_token, encode_access_token
from tests.conftest import TEST_ENV


def test_jti_e_um_uuid_v4():
    _, claims = encode_access_token(uuid.uuid4())
    assert uuid.UUID(claims["jti"]).version == 4


def test_jti_nunca_se_repete():
    usuario = uuid.uuid4()
    jtis = {encode_access_token(usuario)[1]["jti"] for _ in range(500)}
    assert len(jtis) == 500


def test_token_sem_jti_e_rejeitado():
    agora = datetime.now(UTC)
    claims = {
        "iss": "saferdocs",
        "sub": str(uuid.uuid4()),
        "iat": int(agora.timestamp()),
        "exp": int((agora + timedelta(minutes=15)).timestamp()),
    }
    chave = base64.b64decode(TEST_ENV["JWT_PRIVATE_KEY_PEM_B64"])
    token = jwt.encode(claims, chave, algorithm=ALGORITHM)
    with pytest.raises(jwt.MissingRequiredClaimError):
        decode_access_token(token)
