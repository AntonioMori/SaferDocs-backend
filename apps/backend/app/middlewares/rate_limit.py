"""Rate limiting (REQ-05 e REQ-53).

Duas formas de uso:

    # 1) Por IP, como dependência da rota
    @router.post("/verify", dependencies=[Depends(limit_by_ip("verify", settings.rate_limit_verify_per_ip))])

    # 2) Por qualquer chave, dentro do serviço (ex.: por conta no login)
    check_rate_limit("login-account", email.lower(), settings.rate_limit_login_per_account)

Ao estourar, lança AppError(ErrorCode.RATE_LIMITED) com o header Retry-After.
Limites no formato "<quantidade>/<second|minute|hour>", validados no `.env` (RNF-08).

Janela deslizante em memória, por (escopo, chave): uma requisição passa se
houve menos de N aceitas nos últimos T segundos. Requisição recusada não
conta, então quem insiste não estende o próprio bloqueio; o Retry-After é o
tempo até a mais antiga sair da janela.

A API roda num processo só (um worker do uvicorn), então a memória basta. Com
vários processos, cada um teria o próprio contador: aí o estado precisaria ir
para o PostgreSQL ou um Redis. O total de chaves é limitado (MAX_KEYS), para um
atacante que troca de IP ou de e-mail a cada pedido não esgotar a memória; com
a tabela cheia só saem chaves expiradas (examina um lote das mais antigas), e uma
chave nova espera em vez de apagar o contador de outra. Os IPv6 contam pelo /64.
"""

import ipaddress
import math
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from itertools import islice

from fastapi import Request

from app.core.errors import AppError, ErrorCode
from app.core.request_info import client_ip

UNIT_SECONDS = {"second": 1, "minute": 60, "hour": 3600}
MAX_KEYS = 100_000
# Quantas chaves, a partir da mais antiga, o `_evict` examina por vez.
EVICT_BATCH = 256
IPV6_PREFIX = 64

_clock: Callable[[], float] = time.monotonic  # trocado nos testes


def parse_limit(limit: str) -> tuple[int, int]:
    """ "10/minute" -> (10, 60)."""
    count, unit = limit.split("/", 1)
    return int(count), UNIT_SECONDS[unit]


class SlidingWindowLimiter:
    def __init__(self, max_keys: int = MAX_KEYS) -> None:
        # (escopo, chave) -> (janela em segundos, instantes das requisições aceitas).
        # Em ordem de uso: a primeira é a que está há mais tempo sem requisição.
        self._hits: OrderedDict[tuple[str, str], tuple[int, deque[float]]] = OrderedDict()
        self._lock = threading.Lock()
        self._max_keys = max_keys

    def hit(self, scope: str, key: str, count: int, window: int) -> float | None:
        """Registra uma requisição. Devolve None se passou, ou os segundos até poder tentar de novo."""
        with self._lock:
            now = _clock()  # dentro do lock: a ordem dos instantes é a ordem de chegada
            entry = (scope, key)
            current = self._hits.get(entry)
            if current is None:
                if len(self._hits) >= self._max_keys:
                    wait = self._evict(now)
                    if wait is not None:
                        return wait
                hits: deque[float] = deque()
            else:
                hits = current[1]
                self._hits.move_to_end(entry)
            self._hits[entry] = (window, hits)
            while hits and hits[0] <= now - window:
                hits.popleft()
            if len(hits) >= count:
                # Só sai do bloqueio quando sobrarem count-1 na janela.
                return hits[len(hits) - count] + window - now
            hits.append(now)
            return None

    def _evict(self, now: float) -> float | None:
        """Abre espaço tirando chaves cuja janela já passou, entre as mais antigas da fila.

        Examina até EVICT_BATCH chaves a partir do início da fila LRU e apaga as
        expiradas, mesmo as que estão atrás de uma chave ainda ativa (cada janela
        tem o próprio tamanho, então a ordem de uso não é a ordem de expiração).
        Só sai chave expirada: tirar uma ativa zeraria o contador de alguém (um
        atacante encheria a tabela para apagar o bloqueio de uma conta). Se nenhuma
        das examinadas expirou, a chave nova espera (fail closed) e o retorno é quanto.
        Custo limitado por chamada (EVICT_BATCH) e cada chave sai uma vez só.
        Limite conhecido: expiradas além do lote só saem quando chegarem ao início.
        """
        wait: float | None = None
        for entry in list(islice(self._hits, EVICT_BATCH)):
            window, hits = self._hits[entry]
            expires = (hits[-1] + window) if hits else now
            if expires <= now:
                del self._hits[entry]
            elif wait is None or expires - now < wait:
                wait = expires - now
        if len(self._hits) < self._max_keys:
            return None
        return wait if wait is not None else 0.0

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()

    def __len__(self) -> int:
        return len(self._hits)


_limiter = SlidingWindowLimiter()


def reset_rate_limits() -> None:
    """Zera todos os contadores (usado nos testes)."""
    _limiter.reset()


def check_rate_limit(scope: str, key: str, limit: str) -> None:
    """Conta uma requisição de `key` no escopo `scope`; lança ErrorCode.RATE_LIMITED se passar de `limit`."""
    count, window = parse_limit(limit)
    retry_after = _limiter.hit(scope, key, count, window)
    if retry_after is not None:
        raise AppError(ErrorCode.RATE_LIMITED, headers={"Retry-After": str(max(1, math.ceil(retry_after)))})


def ip_bucket(ip: str | None) -> str:
    """Chave do limitador para um IP. IPv6 agrupa pelo /64: uma ligação recebe um /64 inteiro (2^64
    endereços), e sem isso um atacante encheria a tabela só trocando os últimos bits. IPv4 e texto
    que não é IP (ex.: "desconhecido") ficam como vieram."""
    if not ip:
        return "desconhecido"
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:  # ::ffff:1.2.3.4 é o IPv4 1.2.3.4
            return str(address.ipv4_mapped)
        return str(ipaddress.IPv6Network((address, IPV6_PREFIX), strict=False))
    return str(address)


def limit_by_ip(scope: str, limit: str) -> Callable[[Request], None]:
    """Dependência do FastAPI que limita requisições por IP (IPv6 agrupado por /64)."""

    def dependency(request: Request) -> None:
        check_rate_limit(scope, ip_bucket(client_ip(request)), limit)

    return dependency
