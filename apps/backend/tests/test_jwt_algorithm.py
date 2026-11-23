"""REQ-17: JWT assinado com ES256; nunca `alg: none` nem outro algoritmo."""

import base64
import hashlib
import hmac
import json
import uuid

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from app.crypto.jwt import ALGORITHM, decode_access_token, encode_access_token
from tests.conftest import TEST_ENV


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


SESSAO = {"session_id": str(uuid.uuid4())}


def _claims_validos() -> dict:
    _, claims = encode_access_token(uuid.uuid4(), SESSAO)
    return claims


def test_token_emitido_usa_es256():
    token, _ = encode_access_token(uuid.uuid4())
    assert ALGORITHM == "ES256"
    assert jwt.get_unverified_header(token)["alg"] == "ES256"


def test_token_valido_e_aceito():
    token, claims = encode_access_token(uuid.uuid4(), SESSAO)
    assert decode_access_token(token)["jti"] == claims["jti"]


def test_alg_none_e_rejeitado():
    header = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps(_claims_validos()).encode())
    for token in (f"{header}.{payload}.", f"{header}.{payload}"):
        with pytest.raises(jwt.PyJWTError):
            decode_access_token(token)


def test_confusao_de_algoritmo_hs256_com_a_chave_publica_e_rejeitada():
    # Ataque clássico: assinar com HMAC usando a chave pública (conhecida) como segredo.
    chave_publica = base64.b64decode(TEST_ENV["JWT_PUBLIC_KEY_PEM_B64"])
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64url(json.dumps(_claims_validos()).encode())
    assinatura = _b64url(hmac.new(chave_publica, f"{header}.{payload}".encode(), hashlib.sha256).digest())
    with pytest.raises(jwt.PyJWTError):
        decode_access_token(f"{header}.{payload}.{assinatura}")


def test_rs256_e_rejeitado_mesmo_bem_assinado():
    chave = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode(_claims_validos(), chave, algorithm="RS256")
    with pytest.raises(jwt.PyJWTError):
        decode_access_token(token)


def test_es256_assinado_por_outra_chave_e_rejeitado():
    outra = ec.generate_private_key(ec.SECP256R1())
    pem = outra.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    with pytest.raises(jwt.InvalidSignatureError):
        decode_access_token(jwt.encode(_claims_validos(), pem, algorithm="ES256"))


def test_payload_adulterado_e_rejeitado():
    token, claims = encode_access_token(uuid.uuid4())
    header, _, assinatura = token.split(".")
    adulterado = _b64url(json.dumps({**claims, "sub": str(uuid.uuid4())}).encode())
    with pytest.raises(jwt.InvalidSignatureError):
        decode_access_token(f"{header}.{adulterado}.{assinatura}")


def test_emissor_diferente_e_rejeitado():
    token, _ = encode_access_token(uuid.uuid4(), {**SESSAO, "iss": "outro-sistema"})
    with pytest.raises(jwt.InvalidIssuerError):
        decode_access_token(token)
