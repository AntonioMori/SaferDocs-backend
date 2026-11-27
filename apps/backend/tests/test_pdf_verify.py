"""Verificação criptográfica no worker (REQ-50): CMS, integridade e cobertura do arquivo."""

import datetime as dt
import io
from unittest import mock

import pytest
from cryptography.hazmat.primitives import serialization

from app.core.errors import AppError, ErrorCode
from app.crypto.cms import build_signed_data
from app.pdf import client as pdf_client
from app.services.user_keys import sign_with_user_key
from tests.conftest import make_pdf, make_signer


def assinar(pdf: bytes, assinante=None, *, por_fora: bool = False):
    """Assina com o worker. `por_fora` simula outra ferramenta, que não recusa um PDF que o
    SaferDocs já assinou (o SaferDocs recusa: DOC_006)."""
    user, cert_pem = assinante or make_signer()
    trava = mock.patch("pdf_worker.sign._already_signed_by", return_value=False) if por_fora else None
    with trava or mock.MagicMock():
        preparado = pdf_client.prepare_sign(
            pdf, page=1, x=10, y=10, seal_lines=["Teste"], signer_cert_pem=cert_pem
        )
    cms = build_signed_data(
        document_digest=preparado.digest,
        signer_cert_der=user.signing_cert,
        signing_time=dt.datetime.now(dt.UTC),
        sign=lambda dados: sign_with_user_key(user, dados),
    )
    return pdf_client.finish_sign(preparado.prepared_pdf, cms), user


def test_pdf_assinado_intacto_confere(fake_pdf_worker):
    assinado, user = assinar(make_pdf())
    resultado = pdf_client.verify(assinado)
    assert resultado.has_signature and resultado.cms_valid and resultado.covers_whole_file
    assert resultado.signer_public_key_der == user.signing_public_key


def test_pdf_sem_assinatura_nao_tem_assinatura(fake_pdf_worker):
    resultado = pdf_client.verify(make_pdf())
    assert not resultado.has_signature
    assert resultado.signer_public_key_der is None


def test_selo_desenhado_sem_assinatura_nao_conta(fake_pdf_worker):
    # Critério de aceite: só o visual do selo (texto na página) não é assinatura.
    from tests.test_pdf_javascript import raw_pdf, stream

    desenho = b"BT /F1 10 Tf 20 20 Td (Assinado por: Ana Souza  SHA-256: abc  ID: 123) Tj ET"
    pdf = raw_pdf(
        {
            3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R >>",
            4: stream(desenho),
        }
    )
    assert pdf_client.verify(pdf).has_signature is False


def test_um_byte_alterado_invalida_o_cms(fake_pdf_worker):
    assinado, _ = assinar(make_pdf())
    alterado = bytearray(assinado)
    posicao = alterado.index(b"/MediaBox") + 12
    alterado[posicao] ^= 0x01
    resultado = pdf_client.verify(bytes(alterado))
    assert resultado.has_signature
    assert not resultado.cms_valid


def test_alteracao_incremental_depois_de_assinar_nao_cobre_o_arquivo(fake_pdf_worker):
    # Uma revisão acrescentada depois (aqui, girar a página) deixa a assinatura válida para
    # a parte antiga, mas ela não cobre mais o arquivo inteiro: conta como adulterado.
    from pyhanko.pdf_utils.generic import NameObject, NumberObject
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

    assinado, _ = assinar(make_pdf())
    escritor = IncrementalPdfFileWriter(io.BytesIO(assinado))
    pagina = escritor.root["/Pages"]["/Kids"][0].get_object()
    pagina[NameObject("/Rotate")] = NumberObject(90)
    escritor.update_container(pagina)
    saida = io.BytesIO()
    escritor.write(saida)
    resultado = pdf_client.verify(saida.getvalue())
    assert resultado.has_signature and resultado.cms_valid
    assert not resultado.covers_whole_file


def test_cms_forjado_com_outra_chave_e_invalido(fake_pdf_worker):
    # Certificado de um usuário, assinatura feita com a chave de outro.
    vitima, impostor = make_signer(), make_signer()
    preparado = pdf_client.prepare_sign(
        make_pdf(), page=1, x=10, y=10, seal_lines=["x"], signer_cert_pem=vitima[1]
    )
    cms = build_signed_data(
        document_digest=preparado.digest,
        signer_cert_der=vitima[0].signing_cert,
        signing_time=dt.datetime.now(dt.UTC),
        sign=lambda dados: sign_with_user_key(impostor[0], dados),
    )
    resultado = pdf_client.verify(pdf_client.finish_sign(preparado.prepared_pdf, cms))
    assert resultado.has_signature and not resultado.cms_valid


def test_chave_publica_devolvida_e_a_do_certificado_embutido(fake_pdf_worker):
    assinado, user = assinar(make_pdf())
    chave = serialization.load_der_public_key(pdf_client.verify(assinado).signer_public_key_der)
    assert (
        chave.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        == user.signing_public_key
    )


def test_verificacao_recusa_pdf_com_javascript(fake_pdf_worker):
    from tests.test_pdf_javascript import COM_JAVASCRIPT, raw_pdf

    with pytest.raises(AppError) as erro:
        pdf_client.verify(raw_pdf(COM_JAVASCRIPT["open-action"]))
    assert erro.value.code == ErrorCode.DOC_HAS_JAVASCRIPT
