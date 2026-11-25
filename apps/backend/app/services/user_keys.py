"""Chaves de assinatura por usuário (REQ-45 e REQ-59).

Chamada no cadastro, depois de o usuário ser criado:

    generate_user_keys(db, user)

Gera um par ECDSA P-256 e um certificado X.509 autoassinado com o nome do
usuário (o CMS embutido no PDF carrega o certificado de quem assinou).
Preenche `user.signing_public_key` (SubjectPublicKeyInfo DER),
`user.signing_cert` (DER) e `user.signing_private_key_enc`: a privada em
PKCS#8, cifrada com AES-256-GCM numa chave derivada da MASTER_KEY só para
isso (`AeadContext.SIGNING_KEY`), com o id do usuário como dado associado.
Não faz commit: quem chama controla a transação.

A privada decifrada nunca sai deste módulo (REQ-59): `sign_with_user_key`
recebe os bytes a assinar e devolve só a assinatura. Ela não é logada, não
volta em resposta nem aparece em mensagem de erro.
"""

import datetime as dt
import unicodedata

from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from sqlalchemy.orm import Session

from app.core.errors import AppError, ErrorCode
from app.crypto.aead import AeadContext, DecryptionError, decrypt, encrypt
from app.db.models import User

CERT_VALIDITY = dt.timedelta(days=3650)
MAX_CN_LENGTH = 64  # limite do X.520 para o commonName


class Redacted:
    """Guarda bytes sensíveis sem mostrá-los em repr, str, f-string, log ou pickle (REQ-59)."""

    __slots__ = ("_value",)

    def __init__(self, value: bytes) -> None:
        self._value = value

    def reveal(self) -> bytes:
        return self._value

    def __repr__(self) -> str:
        return "<oculto>"

    __str__ = __repr__

    def __format__(self, spec: str) -> str:
        return "<oculto>"

    def __reduce__(self) -> tuple:
        raise TypeError("valor sensível não pode ser serializado")


def certificate_common_name(name: str | None) -> str:
    """Nome do usuário como commonName que qualquer leitor de certificado aceita.

    O X.509 compara nomes com o stringprep (RFC 4518), que recusa caracteres sem
    atribuição no Unicode 3.2, como emoji. Com um deles no CN, o pyHanko não
    consegue nem comparar emissor e titular, e a verificação de um documento
    íntegro falharia. Esses caracteres saem do CN; o nome completo continua no
    cadastro, que é o que a verificação mostra.
    """
    kept = "".join(c for c in (name or "") if unicodedata.ucd_3_2_0.category(c) != "Cn")
    common_name = " ".join(kept.split())[:MAX_CN_LENGTH].strip() or "SaferDocs"
    try:
        asn1_x509.Name.build({"common_name": common_name}).hashable  # noqa: B018 - o stringprep roda aqui
    except ValueError:
        common_name = (
            "".join(c for c in common_name if c.isascii() and c.isprintable()).strip() or "SaferDocs"
        )
    return common_name


def generate_user_keys(db: Session, user: User) -> None:
    """Gera e associa ao usuário o par de chaves de assinatura."""
    del db  # o usuário já está na sessão; quem chama faz o commit
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, certificate_common_name(user.name)),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SaferDocs"),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, str(user.id)),
        ]
    )
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + CERT_VALIDITY)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,  # não repúdio
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )
    private_der = private_key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    user.signing_public_key = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    user.signing_cert = cert.public_bytes(serialization.Encoding.DER)
    user.signing_private_key_enc = encrypt(
        AeadContext.SIGNING_KEY, private_der, associated_data=user.id.bytes
    )


def sign_with_user_key(user: User, data: bytes) -> bytes:
    """Assina `data` (ECDSA P-256 com SHA-256) com a chave privada do usuário. Devolve a assinatura DER.

    A chave é decifrada aqui, usada e descartada. Erros não citam a chave nem o motivo
    criptográfico: qualquer falha vira um erro interno genérico.
    """
    if not user.signing_private_key_enc:
        raise AppError(ErrorCode.INTERNAL)
    try:
        private_der = Redacted(
            decrypt(AeadContext.SIGNING_KEY, user.signing_private_key_enc, associated_data=user.id.bytes)
        )
        private_key = serialization.load_der_private_key(private_der.reveal(), password=None)
        del private_der
    except (DecryptionError, ValueError):
        raise AppError(ErrorCode.INTERNAL) from None
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise AppError(ErrorCode.INTERNAL)
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))
