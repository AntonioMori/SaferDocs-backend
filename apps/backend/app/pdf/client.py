"""Cliente do pdf-worker isolado (REQ-62).

Todo parsing de PDF acontece no worker, sem rede e sem segredos. A chave
privada do usuário NUNCA vai para o worker: ele prepara o documento e
devolve o digest; a API assina o digest e manda só o CMS de volta.

    prepared = prepare_sign(pdf, page=1, x=400, y=50, seal_lines=[...], signer_cert_pem=cert)
    cms = <API assina prepared.digest com a chave do usuário>
    signed_pdf = finish_sign(prepared.prepared_pdf, cms)
    result = verify(pdf)

Erros do worker viram AppError com ErrorCode.DOC_HAS_JAVASCRIPT,
DOC_UNPROCESSABLE ou DOC_INVALID_POSITION.

STUB (INFRA-02) | implementação real: REQ-46/50/62 (dono: v1ct0rjoao).
Hoje devolve respostas fixas, com as mesmas assinaturas.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class PreparedSignature:
    prepared_pdf: bytes  # PDF com o selo desenhado e o espaço reservado para a assinatura
    digest: bytes  # SHA-256 dos bytes cobertos pelo ByteRange, a ser assinado pela API


@dataclass(frozen=True)
class VerificationResult:
    has_signature: bool  # há assinatura embutida (ISO 32000)?
    cms_valid: bool  # o CMS confere com o conteúdo coberto?
    covers_whole_file: bool  # a assinatura cobre o arquivo inteiro (sem alteração incremental)?
    signer_public_key_der: bytes | None  # chave pública do certificado do assinante
    signature_id: str | None  # id da assinatura lido do documento, se houver


def prepare_sign(
    pdf: bytes, *, page: int, x: float, y: float, seal_lines: list[str], signer_cert_pem: bytes
) -> PreparedSignature:
    del page, x, y, seal_lines, signer_cert_pem  # usados pela implementação real
    return PreparedSignature(prepared_pdf=pdf, digest=b"\x00" * 32)


def finish_sign(prepared_pdf: bytes, cms: bytes) -> bytes:
    del cms  # usado pela implementação real
    return prepared_pdf


def verify(pdf: bytes) -> VerificationResult:
    del pdf  # usado pela implementação real
    return VerificationResult(
        has_signature=False,
        cms_valid=False,
        covers_whole_file=False,
        signer_public_key_der=None,
        signature_id=None,
    )
