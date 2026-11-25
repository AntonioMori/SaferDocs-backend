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
    for i in range(1000):  # atacante trocando de chave a cada pedido, com as antigas já expiradas
        relogio.agora = 1000 + i * 61
        limiter.hit("s", f"k{i}", 5, 60)
    assert len(limiter) <= 100


def test_tabela_cheia_nao_apaga_o_contador_de_quem_esta_bloqueado(relogio):
    # QA: encher a tabela com chaves novas não pode zerar o bloqueio de uma conta.
    limiter = SlidingWindowLimiter(max_keys=10)
    relogio.agora = 1000
    for _ in range(3):
        limiter.hit("login-account", "vitima@x.dev", 3, 3600)
    assert limiter.hit("login-account", "vitima@x.dev", 3, 3600) is not None
    for i in range(50):
        relogio.agora = 1000 + i
        limiter.hit("login-account", f"lixo{i}@x.dev", 3, 3600)
    assert len(limiter) <= 10
    assert limiter.hit("login-account", "vitima@x.dev", 3, 3600) is not None


def test_tabela_cheia_de_chaves_ativas_faz_a_nova_esperar(relogio):
    limiter = SlidingWindowLimiter(max_keys=2)
    relogio.agora = 1000
    assert limiter.hit("s", "a", 5, 60) is None
    relogio.agora = 1010
    assert limiter.hit("s", "b", 5, 60) is None
    espera = limiter.hit("s", "c", 5, 60)
    assert espera == 50  # até "a" expirar
    relogio.agora = 1061
    assert limiter.hit("s", "c", 5, 60) is None  # "a" expirou e saiu
    assert limiter.hit("s", "b", 5, 60) is None  # "b" continua com o contador


def test_chave_expirada_atras_de_uma_ativa_tambem_e_removida(relogio):
    # QA (M4): a fila é por uso, não por expiração; a expirada não pode ficar presa atrás da ativa.
    limiter = SlidingWindowLimiter(max_keys=3)
    relogio.agora = 1000
    limiter.hit("hora", "ativa", 5, 3600)
    limiter.hit("s", "curta1", 5, 60)
    limiter.hit("s", "curta2", 5, 60)
    relogio.agora = 1100
    assert limiter.hit("s", "nova", 5, 60) is None
    assert len(limiter) <= 3
    # A ativa continua com o contador dela.
    assert limiter.hit("hora", "ativa", 1, 3600) is not None


def test_o_lote_examinado_e_limitado(relogio, monkeypatch):
    monkeypatch.setattr(rate_limit, "EVICT_BATCH", 2)
    limiter = SlidingWindowLimiter(max_keys=4)
    relogio.agora = 1000
    for chave in ("a", "b"):
        limiter.hit("hora", chave, 5, 3600)  # ativas, na frente da fila
    for chave in ("c", "d"):
        limiter.hit("s", chave, 5, 60)  # expiradas, fora do lote
    relogio.agora = 1100
    assert limiter.hit("s", "nova", 5, 60) is not None  # fail closed: o lote só viu chaves ativas


def test_chave_usada_ha_pouco_vai_para_o_fim_da_fila_e_nao_e_a_examinada(relogio, monkeypatch):
    # QA (R04, move_to_end): com o lote de 1, a chave antiga mas usada agora não pode ser a examinada.
    monkeypatch.setattr(rate_limit, "EVICT_BATCH", 1)
    limiter = SlidingWindowLimiter(max_keys=3)
    for instante, chave in ((1000, "a"), (1001, "b"), (1002, "c")):
        relogio.agora = instante
        limiter.hit("s", chave, 5, 60)
    relogio.agora = 1050
    limiter.hit("s", "a", 5, 60)  # "a" é a mais antiga, mas acabou de ser usada
    relogio.agora = 1070  # "b" e "c" expiraram; "a" não
    assert limiter.hit("s", "d", 5, 60) is None
    assert limiter.hit("s", "a", 1, 60) is not None  # "a" manteve a requisição de 1050


def test_ipv6_do_mesmo_64_divide_o_balde(relogio):
    from starlette.requests import Request

    def pedido(ip):
        return Request({"type": "http", "client": (ip, 1234), "headers": []})

    dependencia = rate_limit.limit_by_ip("v6", "2/minute")
    dependencia(pedido("2001:db8:1:2::1"))
    dependencia(pedido("2001:db8:1:2:ffff:ffff:ffff:ffff"))
    with pytest.raises(AppError) as erro:
        dependencia(pedido("2001:db8:1:2:abcd::9"))
    assert erro.value.code == ErrorCode.RATE_LIMITED
    dependencia(pedido("2001:db8:1:3::1"))  # outro /64 tem o próprio balde


def test_ip_bucket():
    assert rate_limit.ip_bucket("2001:db8:1:2::1") == "2001:db8:1:2::/64"
    assert rate_limit.ip_bucket("2001:0DB8:1:2::1") == rate_limit.ip_bucket("2001:db8:1:2:0:0:0:2")
    assert rate_limit.ip_bucket("203.0.113.7") == "203.0.113.7"
    assert rate_limit.ip_bucket("::ffff:203.0.113.7") == "203.0.113.7"
    assert rate_limit.ip_bucket("desconhecido") == "desconhecido"  # não é IP: fica como veio
    assert rate_limit.ip_bucket(None) == "desconhecido"
    assert rate_limit.ip_bucket("") == "desconhecido"


def test_expiracao_usa_a_janela_de_cada_chave(relogio):
    # QA: a chave de janela de 1 h não pode sair porque a chave nova usa janela de 1 min.
    limiter = SlidingWindowLimiter(max_keys=1)
    relogio.agora = 1000
    limiter.hit("hora", "a", 1, 3600)
    relogio.agora = 1100
    assert limiter.hit("minuto", "b", 1, 60) is not None
    assert limiter.hit("hora", "a", 1, 3600) is not None


def test_retry_after_espera_ate_caber_de_novo(relogio):
    limiter = SlidingWindowLimiter()
    for t in (1000, 1010, 1020):
        relogio.agora = t
        limiter.hit("s", "k", 3, 60)
    relogio.agora = 1030
    assert limiter.hit("s", "k", 3, 60) == 30  # a de 1000 sai em 1060


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
