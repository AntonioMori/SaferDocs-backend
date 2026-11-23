"""REQ-02: senhas guardadas com Argon2id (RFC 9106: m=64MB, t=3, p=4)."""

from argon2 import PasswordHasher

from app.crypto.passwords import dummy_hash, hash_password, needs_rehash, verify_password

SENHA = "Senha-Forte#2026"


def test_hash_usa_argon2id_com_parametros_da_rfc_9106():
    assert hash_password(SENHA).startswith("$argon2id$v=19$m=65536,t=3,p=4$")


def test_salt_aleatorio():
    assert hash_password(SENHA) != hash_password(SENHA)


def test_hash_nao_contem_a_senha():
    assert SENHA not in hash_password(SENHA)


def test_verifica_senha_correta_e_errada():
    hashed = hash_password(SENHA)
    assert verify_password(hashed, SENHA)
    assert not verify_password(hashed, SENHA + "x")


def test_hash_invalido_ou_de_outro_algoritmo_falha_sem_excecao():
    assert not verify_password("!dev-token-sem-senha", SENHA)
    assert not verify_password("$2b$12$abcdefghijklmnopqrstuuOq1f6Uq8xnDJ0wE0r0x2e0lHGn2Z0y", SENHA)


def test_hash_com_parametros_antigos_precisa_de_rehash():
    antigo = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash(SENHA)
    assert needs_rehash(antigo)
    assert not needs_rehash(hash_password(SENHA))


def test_dummy_hash_e_argon2id():
    assert dummy_hash().startswith("$argon2id$")
