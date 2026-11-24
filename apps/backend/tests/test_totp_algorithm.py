"""REQ-11: TOTP RFC 6238, janela de 30 s, tolerância de ±1 janela e sem reuso do código."""

import pyotp
import pytest

from app.crypto import totp

SEGREDO = pyotp.random_base32(32)
AGORA = 1_795_000_015.0  # meio de uma janela de 30 s
PASSO = int(AGORA // 30)


def _codigo(deslocamento: int) -> str:
    return totp.code_at_step(SEGREDO, PASSO + deslocamento)


def test_compativel_com_os_vetores_da_rfc_6238():
    # RFC 6238, apêndice B (SHA-1, segredo "12345678901234567890", 8 dígitos): T = 59 s -> 94287082.
    segredo = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    assert pyotp.TOTP(segredo, digits=8).at(59) == "94287082"
    assert totp.code_at_step(segredo, 59 // 30) == "287082"  # mesmos 6 últimos dígitos


def test_codigo_da_janela_atual_e_aceito():
    assert totp.verify(SEGREDO, _codigo(0), None, now=AGORA) == PASSO


@pytest.mark.parametrize("deslocamento", [-1, 1], ids=["anterior", "seguinte"])
def test_janela_vizinha_e_aceita(deslocamento):
    assert totp.verify(SEGREDO, _codigo(deslocamento), None, now=AGORA) == PASSO + deslocamento


@pytest.mark.parametrize("deslocamento", [-2, 2, -10], ids=["dois-antes", "dois-depois", "antigo"])
def test_dois_passos_fora_e_recusado(deslocamento):
    assert totp.verify(SEGREDO, _codigo(deslocamento), None, now=AGORA) is None


def test_mesmo_codigo_nao_serve_duas_vezes():
    passo = totp.verify(SEGREDO, _codigo(0), None, now=AGORA)
    assert totp.verify(SEGREDO, _codigo(0), passo, now=AGORA + 5) is None


def test_codigo_de_janela_ja_superada_e_recusado():
    passo = totp.verify(SEGREDO, _codigo(1), None, now=AGORA)
    assert totp.verify(SEGREDO, _codigo(0), passo, now=AGORA) is None  # válido no tempo, mas anterior


def test_codigo_da_janela_seguinte_ao_ultimo_uso_e_aceito():
    assert totp.verify(SEGREDO, _codigo(0), PASSO - 1, now=AGORA) == PASSO


@pytest.mark.parametrize("codigo", ["", "12345", "1234567", "abcdef", "12 34 5x"])
def test_formato_invalido_e_recusado(codigo):
    assert totp.verify(SEGREDO, codigo, None, now=AGORA) is None


def test_espacos_sao_ignorados():
    codigo = _codigo(0)
    assert totp.verify(SEGREDO, f" {codigo[:3]} {codigo[3:]} ", None, now=AGORA) == PASSO


def test_segredo_errado_e_recusado():
    assert totp.verify(pyotp.random_base32(32), _codigo(0), None, now=AGORA) is None
