"""Hash de senhas com Argon2id (REQ-02).

Parâmetros recomendados pela RFC 9106: memória de 64 MiB, 3 iterações e
paralelismo 4. Nunca usar bcrypt, scrypt, MD5, SHA-1 ou SHA-256 simples.
"""

from functools import lru_cache

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

MEMORY_COST_KIB = 64 * 1024  # 64 MiB
TIME_COST = 3
PARALLELISM = 4

_hasher = PasswordHasher(
    time_cost=TIME_COST,
    memory_cost=MEMORY_COST_KIB,
    parallelism=PARALLELISM,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)


def hash_password(password: str) -> str:
    """Hash Argon2id com salt aleatório, no formato PHC ($argon2id$v=19$m=65536,t=3,p=4$...)."""
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Confere a senha em tempo constante. Hash inválido ou de outro formato conta como falha."""
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    """True se o hash foi gerado com parâmetros diferentes dos atuais."""
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


@lru_cache
def dummy_hash() -> str:
    """Hash fixo por processo, usado para gastar o mesmo tempo quando o usuário não existe (REQ-04)."""
    return _hasher.hash("saferdocs-usuario-inexistente")
