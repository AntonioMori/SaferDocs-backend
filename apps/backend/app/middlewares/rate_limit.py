"""Rate limiting (REQ-05 e REQ-53).

Duas formas de uso:

    # 1) Por IP, como dependência da rota
    @router.post("/verify", dependencies=[Depends(limit_by_ip("verify", settings.rate_limit_verify_per_ip))])

    # 2) Por qualquer chave, dentro do serviço (ex.: por conta no login)
    check_rate_limit("login-account", email.lower(), settings.rate_limit_login_per_account)

Ao estourar, lança AppError(ErrorCode.RATE_LIMITED) com o header Retry-After.
Limites no formato "<quantidade>/<second|minute|hour>".

STUB (INFRA-02) | implementação real: REQ-05/REQ-53 (dono: v1ct0rjoao).
Hoje deixa tudo passar, com a mesma assinatura.
"""

from collections.abc import Callable

from fastapi import Request

from app.core.request_info import client_ip


def check_rate_limit(scope: str, key: str, limit: str) -> None:
    """Conta uma requisição de `key` no escopo `scope`; lança ErrorCode.RATE_LIMITED se passar de `limit`."""
    del scope, key, limit  # usados pela implementação real


def limit_by_ip(scope: str, limit: str) -> Callable[[Request], None]:
    """Dependência do FastAPI que limita requisições por IP."""

    def dependency(request: Request) -> None:
        check_rate_limit(scope, client_ip(request) or "desconhecido", limit)

    return dependency
