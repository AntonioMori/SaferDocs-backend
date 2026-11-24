"""RNF-08: variáveis validadas na inicialização, sem vazar valores."""

import base64
import secrets

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from app.core.config import ConfigError, load_settings
from tests.conftest import TEST_ENV


@pytest.fixture(autouse=True)
def _sem_arquivo_env(monkeypatch, tmp_path):
    # Isola do .env local do desenvolvedor.
    monkeypatch.chdir(tmp_path)


def _erro(monkeypatch, **valores) -> str:
    for nome, valor in valores.items():
        if valor is None:
            monkeypatch.delenv(nome, raising=False)
        else:
            monkeypatch.setenv(nome, valor)
    with pytest.raises(ConfigError) as excinfo:
        load_settings()
    return str(excinfo.value)


def test_ambiente_valido_carrega():
    assert load_settings().app_env == "test"


@pytest.mark.parametrize(
    "variavel", ["DATABASE_URL", "MASTER_KEY", "JWT_PRIVATE_KEY_PEM_B64", "WEBAUTHN_RP_ID"]
)
def test_variavel_obrigatoria_ausente_impede_subir(monkeypatch, variavel):
    mensagem = _erro(monkeypatch, **{variavel: None})
    assert variavel in mensagem
    assert "obrigatória ausente" in mensagem


def test_master_key_curta_e_recusada_sem_mostrar_o_valor(monkeypatch):
    curta = base64.b64encode(secrets.token_bytes(16)).decode()
    mensagem = _erro(monkeypatch, MASTER_KEY=curta)
    assert "MASTER_KEY" in mensagem
    assert curta not in mensagem


def test_cors_com_asterisco_e_recusado(monkeypatch):
    assert "CORS_ALLOWED_ORIGINS" in _erro(monkeypatch, CORS_ALLOWED_ORIGINS="*")


def test_origem_com_caminho_e_recusada(monkeypatch):
    assert "CORS_ALLOWED_ORIGINS" in _erro(monkeypatch, CORS_ALLOWED_ORIGINS="http://localhost:3039/app")


def test_banco_que_nao_e_postgres_e_recusado(monkeypatch):
    assert "DATABASE_URL" in _erro(monkeypatch, DATABASE_URL="sqlite:///x.db")


def test_chave_jwt_que_nao_e_es256_e_recusada(monkeypatch):
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = rsa_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    pub = rsa_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    mensagem = _erro(
        monkeypatch,
        JWT_PRIVATE_KEY_PEM_B64=base64.b64encode(pem).decode(),
        JWT_PUBLIC_KEY_PEM_B64=base64.b64encode(pub).decode(),
    )
    assert "ES256" in mensagem


def test_chave_publica_de_outro_par_e_recusada(monkeypatch):
    outra = ec.generate_private_key(ec.SECP256R1()).public_key()
    pub = outra.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert "não corresponde" in _erro(monkeypatch, JWT_PUBLIC_KEY_PEM_B64=base64.b64encode(pub).decode())


def test_pem_invalido_nao_vaza_conteudo(monkeypatch):
    lixo = base64.b64encode(b"isto nao e um pem").decode()
    mensagem = _erro(monkeypatch, JWT_PRIVATE_KEY_PEM_B64=lixo)
    assert lixo not in mensagem


def test_origem_webauthn_fora_do_rp_id_e_recusada(monkeypatch):
    assert "WEBAUTHN_ORIGIN" in _erro(monkeypatch, WEBAUTHN_ORIGIN="https://evil.example")


def test_producao_exige_https(monkeypatch):
    mensagem = _erro(monkeypatch, APP_ENV="production")
    assert "https" in mensagem


def test_rate_limit_em_formato_invalido(monkeypatch):
    assert "RATE_LIMIT_LOGIN_PER_IP" in _erro(monkeypatch, RATE_LIMIT_LOGIN_PER_IP="dez por minuto")


def test_valores_do_ambiente_de_teste_nunca_aparecem_nas_mensagens(monkeypatch):
    mensagem = _erro(monkeypatch, APP_ENV="production", RATE_LIMIT_VERIFY_PER_IP="x")
    for nome in ("MASTER_KEY", "HASH_PEPPER", "JWT_PRIVATE_KEY_PEM_B64"):
        assert TEST_ENV[nome] not in mensagem


def test_origem_com_query_fragmento_credencial_ou_porta_invalida_e_recusada(monkeypatch):
    for origem in (
        "https://a.example?x=1",
        "https://a.example#x",
        "https://user:senha@a.example",
        "https://a.example:99999",
        "ftp://a.example",
    ):
        assert "CORS_ALLOWED_ORIGINS" in _erro(monkeypatch, CORS_ALLOWED_ORIGINS=origem), origem
