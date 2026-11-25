"""Par de chaves por usuário (REQ-45)."""

import uuid

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.errors import AppError
from app.crypto.aead import AeadContext, DecryptionError, decrypt
from app.db.models import User
from app.db.session import get_sessionmaker
from app.main import app
from app.services.user_keys import generate_user_keys, sign_with_user_key

SENHA = "Senha-Forte#2026"


@pytest.fixture
def usuario(migrated_db):
    email = f"chaves-{uuid.uuid4().hex[:10]}@teste.dev"
    resposta = TestClient(app).post(
        "/api/v1/auth/register", json={"name": "João Conceição", "email": email, "password": SENHA}
    )
    assert resposta.status_code == 201
    with get_sessionmaker()() as db:
        yield db.scalar(select(User).where(User.email == email))


def test_usuario_recem_criado_tem_publica_certificado_e_privada_cifrada(usuario):
    # Critério de aceite do REQ-45.
    assert usuario.signing_public_key and usuario.signing_cert and usuario.signing_private_key_enc
    publica = serialization.load_der_public_key(usuario.signing_public_key)
    assert isinstance(publica, ec.EllipticCurvePublicKey)
    assert isinstance(publica.curve, ec.SECP256R1)


def test_certificado_autoassinado_com_o_nome_e_a_chave_do_usuario(usuario):
    cert = x509.load_der_x509_certificate(usuario.signing_cert)
    assert cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == "João Conceição"
    assert cert.issuer == cert.subject
    assert (
        cert.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        == usuario.signing_public_key
    )
    uso = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert uso.digital_signature and uso.content_commitment and not uso.key_cert_sign
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False


def test_privada_esta_cifrada_e_amarrada_ao_usuario(usuario):
    cifrada = usuario.signing_private_key_enc
    assert b"PRIVATE KEY" not in cifrada
    privada = serialization.load_der_private_key(
        decrypt(AeadContext.SIGNING_KEY, cifrada, associated_data=usuario.id.bytes), password=None
    )
    assert (
        privada.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        == usuario.signing_public_key
    )
    with pytest.raises(DecryptionError):  # outro usuário (dado associado diferente) não abre
        decrypt(AeadContext.SIGNING_KEY, cifrada, associated_data=uuid.uuid4().bytes)
    with pytest.raises(DecryptionError):  # o contexto do TOTP não abre
        decrypt(AeadContext.TOTP_SECRET, cifrada, associated_data=usuario.id.bytes)


def test_cada_usuario_tem_um_par_diferente(migrated_db):
    a, b = (
        User(id=uuid.uuid4(), name="A", email="a@x", password_hash="!"),
        User(id=uuid.uuid4(), name="B", email="b@x", password_hash="!"),
    )
    generate_user_keys(None, a)  # type: ignore[arg-type]
    generate_user_keys(None, b)  # type: ignore[arg-type]
    assert a.signing_public_key != b.signing_public_key


def test_assinatura_com_a_chave_do_usuario_confere_com_a_publica(usuario):
    assinatura = sign_with_user_key(usuario, b"dados")
    publica = serialization.load_der_public_key(usuario.signing_public_key)
    publica.verify(assinatura, b"dados", ec.ECDSA(hashes.SHA256()))
    with pytest.raises(InvalidSignature):
        publica.verify(assinatura, b"outros dados", ec.ECDSA(hashes.SHA256()))


def test_privada_adulterada_vira_erro_interno_generico(usuario):
    usuario.signing_private_key_enc = usuario.signing_private_key_enc[:-1] + b"\x00"
    with pytest.raises(AppError) as erro:
        sign_with_user_key(usuario, b"dados")
    assert erro.value.code.value == "SYS_001"
