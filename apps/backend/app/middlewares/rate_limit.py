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
atacante que troca de IP ou de e-mail a cada pedido não esgotar a memória.
"""

import math
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable

from fastapi import Request

from app.core.errors import AppError, ErrorCode
from app.core.request_info import client_ip

UNIT_SECONDS = {"second": 1, "minute": 60, "hour": 3600}
MAX_KEYS = 100_000

_clock: Callable[[], float] = time.monotonic  # trocado nos testes


def parse_limit(limit: str) -> tuple[int, int]:
    """ "10/minute" -> (10, 60)."""
    count, unit = limit.split("/", 1)
    return int(count), UNIT_SECONDS[unit]


class SlidingWindowLimiter:
    def __init__(self, max_keys: int = MAX_KEYS) -> None:
        self._hits: OrderedDict[tuple[str, str], deque[float]] = OrderedDict()
        self._lock = threading.Lock()
        self._max_keys = max_keys

    def hit(self, scope: str, key: str, count: int, window: int) -> float | None:
        """Registra uma requisição. Devolve None se passou, ou os segundos até poder tentar de novo."""
        now = _clock()
        with self._lock:
            entry = (scope, key)
            hits = self._hits.get(entry)
            if hits is None:
                if len(self._hits) >= self._max_keys:
                    self._evict(now, window)
                hits = self._hits[entry] = deque()
            else:
                self._hits.move_to_end(entry)
            while hits and hits[0] <= now - window:
                hits.popleft()
            if len(hits) >= count:
                return hits[0] + window - now
            hits.append(now)
            return None

    def _evict(self, now: float, window: int) -> None:
        """Abre espaço: primeiro as chaves sem requisição recente, senão as menos usadas."""
        expired = [k for k, v in self._hits.items() if not v or v[-1] <= now - window]
        for key in expired:
            del self._hits[key]
        while len(self._hits) >= self._max_keys:
            self._hits.popitem(last=False)

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


def limit_by_ip(scope: str, limit: str) -> Callable[[Request], None]:
    """Dependência do FastAPI que limita requisições por IP."""

    def dependency(request: Request) -> None:
        check_rate_limit(scope, client_ip(request) or "desconhecido", limit)

    return dependency
