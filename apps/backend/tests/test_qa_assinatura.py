"""Correções do QA do bloco de assinatura e verificação (REQ-45 a 54 e 59).

Cada teste reproduz um achado do QA (caixa-branca ou caixa-preta) e fica
como regressão.
"""

import datetime as dt
import hashlib

import pytest
from asn1crypto import cms as asn1_cms

from app.core.errors import AppError, ErrorCode
from app.crypto.cms import build_signed_data
from app.pdf import client as pdf_client
from app.pdf.signature_bytes import SignatureBytesError, check_prepared, embed_cms, reserved_contents
from app.services.user_keys import certificate_common_name, sign_with_user_key
from tests.conftest import make_pdf, make_signer
from tests.test_pdf_verify import assinar

# --------------------------------------------------------------- a API não confia no worker (B1)


def _preparado(pdf: bytes | None = None):
    original = pdf or make_pdf()
    user, cert = make_signer()
    preparado = pdf_client.prepare_sign(original, page=1, x=10, y=10, seal_lines=["x"], signer_cert_pem=cert)
    return original, preparado, user


def test_digest_e_recalculado_pela_api(fake_pdf_worker):
    original, preparado, _ = _preparado()
    regiao = reserved_contents(preparado.prepared_pdf)
    coberto = preparado.prepared_pdf[: regiao.start] + preparado.prepared_pdf[regiao.end :]
    assert preparado.digest == hashlib.sha256(coberto).digest()
    assert preparado.prepared_pdf.startswith(original)


def _worker_que_devolve(monkeypatch, alterar):
    """Worker "comprometido": devolve o resultado do worker de verdade, alterado por `alterar`."""
    real = pdf_client._call

    def call(op, args, pdf):
        resultado, corpo = real(op, args, pdf)
        if op == "prepare_sign":
            return alterar(resultado, corpo)
        return resultado, corpo

    monkeypatch.setattr(pdf_client, "_call", call)


@pytest.mark.parametrize(
    "alterar",
    [
        # digest de outro documento: a API assinaria o que o usuário não mandou
        lambda r, c: ({"digest": "00" * 32}, c),
        # arquivo que não começa com o original
        lambda r, c: (r, c.replace(b"/MediaBox", b"/MediaBoX", 1)),
        # /Contents já preenchido
        lambda r, c: (r, c.replace(b"<" + b"0" * 64, b"<" + b"1" + b"0" * 63, 1)),
        # bytes acrescentados depois do /ByteRange: ele não cobre mais o arquivo inteiro
        lambda r, c: (r, c + b"\n% extra\n"),
    ],
    ids=["digest-trocado", "original-alterado", "contents-preenchido", "byterange-incompleto"],
)
def test_preparado_adulterado_pelo_worker_e_recusado(fake_pdf_worker, monkeypatch, alterar):
    _worker_que_devolve(monkeypatch, alterar)
    with pytest.raises(AppError) as erro:
        _preparado()
    assert erro.value.code == ErrorCode.INTERNAL


def test_byterange_que_estava_no_original_nao_serve(fake_pdf_worker):
    # Um PDF que já tem uma assinatura: o /ByteRange antigo está no original, não na parte nova.
    assinado, _ = assinar(make_pdf())
    with pytest.raises(SignatureBytesError):
        check_prepared(assinado, assinado + b"\n")


def test_contents_reservado_precisa_ser_so_zeros():
    pdf = b"%PDF-1.7\n/ByteRange [0 20 30 0 ]<0000000>"
    pdf = b"%PDF-1.7\n" + b"x" * 11 + b"<00000001>" + b"/ByteRange [0 20 30 13]"
    with pytest.raises(SignatureBytesError):
        reserved_contents(pdf)


def test_cms_e_escrito_so_dentro_do_contents(fake_pdf_worker):
    _, preparado, user = _preparado()
    regiao = reserved_contents(preparado.prepared_pdf)
    cms = build_signed_data(
        document_digest=preparado.digest,
        signer_cert_der=user.signing_cert,
        signing_time=dt.datetime.now(dt.UTC),
        sign=lambda dados: sign_with_user_key(user, dados),
    )
    assinado = embed_cms(preparado.prepared_pdf, regiao, cms)
    assert len(assinado) == len(preparado.prepared_pdf)
    assert assinado[: regiao.start + 1] == preparado.prepared_pdf[: regiao.start + 1]
    assert assinado[regiao.end - 1 :] == preparado.prepared_pdf[regiao.end - 1 :]
    assert bytes.fromhex(assinado[regiao.start + 1 : regiao.start + 1 + len(cms) * 2].decode()) == cms


@pytest.mark.parametrize("cms", [b"", b"\x04abc", b"\x30" * 5000])
def test_cms_vazio_fora_do_formato_ou_grande_demais_e_recusado(fake_pdf_worker, cms):
    _, preparado, _ = _preparado()
    with pytest.raises(AppError) as erro:
        pdf_client.finish_sign(preparado.prepared_pdf, cms)
    assert erro.value.code == ErrorCode.INTERNAL


# --------------------------------------------------------------- PDF sem xref não é regravado (B2)


def test_pdf_que_o_pyhanko_nao_le_e_recusado_em_vez_de_regravado(fake_pdf_worker):
    from tests.test_pdf_javascript import raw_pdf

    sem_xref = raw_pdf({3: b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>"}, xref=False)
    _, cert = make_signer()
    with pytest.raises(AppError) as erro:
        pdf_client.prepare_sign(sem_xref, page=1, x=10, y=10, seal_lines=["x"], signer_cert_pem=cert)
    assert erro.value.code == ErrorCode.DOC_UNPROCESSABLE


# --------------------------------------------------------------- nome com emoji (caixa-preta, alto)


@pytest.mark.parametrize("nome", ["Ana 😀 Lima", "Zhang 张伟", "José Ñúñez", "😀😀"])
def test_nome_com_emoji_ou_cjk_nao_quebra_a_verificacao(fake_pdf_worker, nome):
    assinado, _ = assinar(make_pdf(), make_signer(nome))
    resultado = pdf_client.verify(assinado)
    assert resultado.has_signature and resultado.cms_valid and resultado.covers_whole_file


def test_common_name_tira_so_o_que_o_x509_nao_aceita():
    assert certificate_common_name("Ana 😀 Lima") == "Ana Lima"
    assert certificate_common_name("Zhang 张伟") == "Zhang 张伟"
    assert certificate_common_name("😀") == "SaferDocs"
    assert certificate_common_name(None) == "SaferDocs"
    assert len(certificate_common_name("a" * 200)) == 64


# --------------------------------------------------------------- assinado e corrompido é ADULTERADO


@pytest.mark.parametrize("onde", ["original", "cms", "final"])
def test_pdf_assinado_e_corrompido_e_adulterado_e_nao_pdf_invalido(fake_pdf_worker, onde):
    assinado, _ = assinar(make_pdf())
    inicio_contents = assinado.index(b"/Contents <") + len(b"/Contents <")
    # O miolo do /Contents (o padding zerado) não é coberto pelo /ByteRange: mexer nele não
    # invalida nada. Por isso corrompe a parte original, o começo do CMS e o final do arquivo.
    inicio = {"original": 100, "cms": inicio_contents + 40, "final": len(assinado) - 150}[onde]
    corrompido = assinado[:inicio] + b"\x00" * 60 + assinado[inicio + 60 :]
    resultado = pdf_client.verify(corrompido)
    assert resultado.has_signature and not resultado.cms_valid


def test_dicionario_de_assinatura_malformado_e_adulterado(fake_pdf_worker):
    assinado, _ = assinar(make_pdf())
    quebrado = assinado.replace(b"/SubFilter /adbe.pkcs7.detached", b"/SubFilter 12345678901234567", 1)
    resultado = pdf_client.verify(quebrado)
    assert resultado.has_signature and not resultado.cms_valid


def test_pdf_sem_cara_de_assinado_que_nao_abre_continua_doc_004(fake_pdf_worker):
    with pytest.raises(AppError) as erro:
        pdf_client.verify(b"%PDF-1.7\nlixo")
    assert erro.value.code == ErrorCode.DOC_UNPROCESSABLE


# --------------------------------------------------------------- mutações que sobreviveram


def test_verificacao_usa_a_assinatura_mais_recente(fake_pdf_worker):
    # Assinado duas vezes: a primeira não cobre mais o arquivo; a segunda sim.
    uma_vez, _ = assinar(make_pdf())
    duas_vezes, segundo = assinar(uma_vez, make_signer("Segundo"))
    resultado = pdf_client.verify(duas_vezes)
    assert resultado.cms_valid and resultado.covers_whole_file
    assert resultado.signer_public_key_der == segundo.signing_public_key


def test_cms_leva_o_horario_da_assinatura():
    user, _ = make_signer()
    quando = dt.datetime(2026, 5, 17, 12, 30, tzinfo=dt.UTC)
    der = build_signed_data(
        document_digest=b"\x00" * 32,
        signer_cert_der=user.signing_cert,
        signing_time=quando,
        sign=lambda dados: sign_with_user_key(user, dados),
    )
    info = asn1_cms.ContentInfo.load(der)["content"]["signer_infos"][0]
    atributos = {a["type"].native: a["values"][0].native for a in info["signed_attrs"]}
    assert atributos["signing_time"] == quando


def test_porcentagem_no_selo_sai_literal(fake_pdf_worker):
    # O pyHanko formata o texto do selo com "%"; sem escapar, "%(x)s" quebraria a assinatura.
    user, cert = make_signer()
    preparado = pdf_client.prepare_sign(
        make_pdf(), page=1, x=10, y=10, seal_lines=["100% %(signer)s %s"], signer_cert_pem=cert
    )
    assert len(preparado.digest) == 32
    from pdf_worker.sign import _seal_text

    assert _seal_text(["100% %(signer)s"]) == "100%% %%(signer)s"


def test_banco_nao_loga_parametros_das_consultas():
    from app.db.session import get_engine

    assert get_engine().hide_parameters is True
