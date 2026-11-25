"""CMS (PKCS#7 SignedData) da assinatura do PDF, montado na API (REQ-46).

O worker devolve o SHA-256 dos bytes cobertos pelo /ByteRange do PDF; aqui
esse digest vira o atributo `messageDigest`, os atributos assinados são
assinados com a chave do usuário (ECDSA P-256 + SHA-256) e o resultado é o
CMS destacado ("detached") que o worker escreve no /Contents. É o formato
`adbe.pkcs7.detached` que os leitores de PDF validam.

Só usa asn1crypto e cryptography: nenhuma biblioteca de PDF entra na API.
"""

import datetime as dt
from collections.abc import Callable

from asn1crypto import algos, cms, core, x509

DIGEST_ALGORITHM = "sha256"


def build_signed_data(
    *,
    document_digest: bytes,
    signer_cert_der: bytes,
    signing_time: dt.datetime,
    sign: Callable[[bytes], bytes],
) -> bytes:
    """CMS DER. `sign(dados)` devolve a assinatura ECDSA DER dos dados (a chave fica com quem chama)."""
    if len(document_digest) != 32:
        raise ValueError("o digest precisa ser SHA-256 (32 bytes)")
    cert = x509.Certificate.load(signer_cert_der)
    signed_attrs = cms.CMSAttributes(
        [
            cms.CMSAttribute({"type": "content_type", "values": ["data"]}),
            cms.CMSAttribute({"type": "message_digest", "values": [document_digest]}),
            cms.CMSAttribute(
                {"type": "signing_time", "values": [cms.Time({"utc_time": core.UTCTime(signing_time)})]}
            ),
        ]
    )
    # A assinatura cobre o DER do SET de atributos (RFC 5652, 5.4).
    signature = sign(signed_attrs.dump())
    signer_info = cms.SignerInfo(
        {
            "version": "v1",
            "sid": cms.SignerIdentifier(
                {
                    "issuer_and_serial_number": cms.IssuerAndSerialNumber(
                        {"issuer": cert.issuer, "serial_number": cert.serial_number}
                    )
                }
            ),
            "digest_algorithm": algos.DigestAlgorithm({"algorithm": DIGEST_ALGORITHM}),
            "signed_attrs": signed_attrs,
            "signature_algorithm": algos.SignedDigestAlgorithm({"algorithm": "sha256_ecdsa"}),
            "signature": signature,
        }
    )
    signed_data = cms.SignedData(
        {
            "version": "v1",
            "digest_algorithms": [algos.DigestAlgorithm({"algorithm": DIGEST_ALGORITHM})],
            "encap_content_info": {"content_type": "data"},  # destacado: sem o conteúdo
            "certificates": [cert],
            "signer_infos": [signer_info],
        }
    )
    return cms.ContentInfo({"content_type": "signed_data", "content": signed_data}).dump()
