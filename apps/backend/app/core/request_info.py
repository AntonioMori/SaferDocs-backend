"""Dados de origem da requisição usados em sessões, auditoria e assinaturas."""

from fastapi import Request

MAX_USER_AGENT = 512


def client_ip(request: Request) -> str | None:
    """IP de quem fez a requisição (o proxy reverso deve repassar o IP real)."""
    return request.client.host if request.client else None


def user_agent(request: Request) -> str:
    return request.headers.get("user-agent", "")[:MAX_USER_AGENT]
