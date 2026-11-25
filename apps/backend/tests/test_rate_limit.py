"""Rate limiting (REQ-05): limitador em janela deslizante e o login por IP e por conta."""

import threading
import uuid

import pytest
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.core.errors import AppError, ErrorCode
from app.main import app
from app.middlewares import rate_limit
from app.middlewares.rate_limit import SlidingWindowLimiter, check_rate_limit, parse_limit

SENHA = "Senha-Forte#2026"


class Relogio:
    def __init__(self) -> None:
        self.agora = 1000.0

    def __call__(self) -> float:
        return self.agora


@pytest.fixture
def relogio(monkeypatch):
    r = Relogio()
    monkeypatch.setattr(rate_limit, "_clock", r)
    return r


# --------------------------------------------------------------- limitador


def test_parse_limit():
    assert parse_limit("10/minute") == (10, 60)
    assert parse_limit("5/second") == (5, 1)
    assert parse_limit("100/hour") == (100, 3600)


def test_passa_ate_o_limite_e_recusa_o_seguinte(relogio):
    limiter = SlidingWindowLimiter()
    assert [limiter.hit("s", "k", 10, 60) for _ in range(10)] == [None] * 10
    assert limiter.hit("s", "k", 10, 60) == pytest.approx(60)


def test_janela_e_deslizante(relogio):
    limiter = SlidingWindowLimiter()
    for segundo in range(10):  # uma por segundo
        relogio.agora = 1000 + segundo
        assert limiter.hit("s", "k", 10, 60) is None
    relogio.agora = 1030
    assert limiter.hit("s", "k", 10, 60) == pytest.approx(30)  # a primeira sai em 1060
    relogio.agora = 1060
    assert limiter.hit("s", "k", 10, 60) is None  # a de 1000 saiu da janela


def test_requisicao_recusada_nao_estende_o_bloqueio(relogio):
    limiter = SlidingWindowLimiter()
    for _ in range(3):
        limiter.hit("s", "k", 3, 60)
    for segundo in range(1, 60):  # insiste o minuto todo
        relogio.agora = 1000 + segundo
        assert limiter.hit("s", "k", 3, 60) is not None
    relogio.agora = 1060
    assert limiter.hit("s", "k", 3, 60) is None


def test_escopos_e_chaves_sao_independentes(relogio):
    limiter = SlidingWindowLimiter()
    assert limiter.hit("login-ip", "1.1.1.1", 1, 60) is None
    assert limiter.hit("login-ip", "1.1.1.1", 1, 60) is not None
    assert limiter.hit("login-ip", "2.2.2.2", 1, 60) is None
    assert limiter.hit("verify", "1.1.1.1", 1, 60) is None


def test_memoria_limitada_descarta_chaves_antigas(relogio):
    limiter = SlidingWindowLimiter(max_keys=100)
    for i in range(1000):  # atacante trocando de chave a cada pedido
        relogio.agora = 1000 + i * 0.001
        limiter.hit("s", f"k{i}", 5, 60)
    assert len(limiter) <= 100


def test_concorrencia_nao_deixa_passar_mais_que_o_limite():
    limiter = SlidingWindowLimiter()
    passaram = []

    def tenta():
        if limiter.hit("s", "k", 10, 60) is None:
            passaram.append(1)

    threads = [threading.Thread(target=tenta) for _ in range(200)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(passaram) == 10


def test_check_rate_limit_levanta_429_com_retry_after_inteiro(relogio):
    check_rate_limit("s", "k", "1/minute")
    relogio.agora += 59.2
    with pytest.raises(AppError) as erro:
        check_rate_limit("s", "k", "1/minute")
    assert erro.value.code == ErrorCode.RATE_LIMITED
    assert erro.value.headers == {"Retry-After": "1"}  # 0,8 s arredonda para cima, nunca 0


# --------------------------------------------------------------- login (REQ-05)


@pytest.fixture
def client(migrated_db):
    return TestClient(app)


@pytest.fixture
def conta(client):
    email = f"rl-{uuid.uuid4().hex[:10]}@teste.dev"
    resposta = client.post("/api/v1/auth/register", json={"name": "Ana", "email": email, "password": SENHA})
    assert resposta.status_code == 201
    return email


@pytest.fixture
def limites(monkeypatch):
    def aplicar(ip: str = "1000/minute", conta: str = "1000/minute") -> None:
        monkeypatch.setattr(get_settings(), "rate_limit_login_per_ip", ip)
        monkeypatch.setattr(get_settings(), "rate_limit_login_per_account", conta)

    return aplicar


def _login(client, email, senha="errada-Errada#1"):
    return client.post("/api/v1/auth/login", json={"email": email, "password": senha})


def test_decima_primeira_requisicao_no_minuto_por_ip_recebe_429(client, limites):
    # Critério de aceite: 10/minuto por IP; a 11ª recebe 429 (e-mails diferentes a cada tentativa).
    limites(ip="10/minute")
    respostas = [_login(client, f"x{i}@teste.dev") for i in range(11)]
    assert [r.status_code for r in respostas[:10]] == [401] * 10
    assert respostas[10].status_code == 429
    corpo = respostas[10].json()
    assert corpo["code"] == "RATE_001"
    assert int(respostas[10].headers["retry-after"]) >= 1


def test_limite_por_conta_vale_mesmo_trocando_de_ip_ou_de_caixa(client, limites, conta):
    limites(conta="5/minute")
    variacoes = [conta, conta.upper(), f"  {conta}  ", conta.capitalize(), conta]
    assert [_login(client, e).status_code for e in variacoes] == [401] * 5
    assert _login(client, conta).status_code == 429


def test_conta_inexistente_tem_o_mesmo_limite_sem_revelar_nada(client, limites, conta):
    # REQ-04: o 429 aparece igual para conta que existe e que não existe.
    limites(conta="2/minute")
    for email in (conta, f"nao-existe-{uuid.uuid4().hex[:6]}@teste.dev"):
        respostas = [_login(client, email) for _ in range(3)]
        assert [r.status_code for r in respostas] == [401, 401, 429]


def test_rate_limit_barra_antes_do_argon2(client, limites, monkeypatch):
    # O 429 não gasta o hash da senha: força bruta não vira negação de serviço por CPU.
    from app.services import auth_service

    limites(ip="1/minute")
    _login(client, "a@teste.dev")
    chamadas = []
    monkeypatch.setattr(auth_service, "verify_password", lambda *a: chamadas.append(1) or False)
    assert _login(client, "b@teste.dev").status_code == 429
    assert chamadas == []


def test_429_tem_headers_de_seguranca_e_retry_after_legivel_pelo_front(client, limites):
    limites(ip="1/minute")
    _login(client, "a@teste.dev")
    resposta = client.post(
        "/api/v1/auth/login",
        json={"email": "a@teste.dev", "password": "x"},
        headers={"Origin": "http://localhost:3039"},
    )
    assert resposta.status_code == 429
    assert resposta.headers["cache-control"] == "no-store"
    assert "Retry-After" in resposta.headers["access-control-expose-headers"]


def test_login_com_totp_tambem_e_limitado_por_ip(client, limites):
    limites(ip="2/minute")
    for _ in range(2):
        client.post("/api/v1/auth/login/totp", json={"mfa_token": "x" * 43, "code": "123456"})
    resposta = client.post("/api/v1/auth/login/totp", json={"mfa_token": "x" * 43, "code": "123456"})
    assert resposta.status_code == 429


def test_quantidade_zero_e_recusada_na_configuracao(monkeypatch, tmp_path):
    from app.core.config import ConfigError, load_settings

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("RATE_LIMIT_LOGIN_PER_IP", "0/minute")
    with pytest.raises(ConfigError, match="RATE_LIMIT_LOGIN_PER_IP"):
        load_settings()
