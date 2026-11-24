"""TOTP (RFC 6238) com janela de 30 s e tolerância de ±1 janela (REQ-11).

`verify` devolve o passo de tempo (timestep) aceito, para quem chama gravá-lo
em `users.totp_last_step`. Um código só é aceito se o passo dele for maior
que o último usado: assim o mesmo código não serve duas vezes, nem dentro
da própria janela de 90 s em que continua válido.
"""

import hmac
import time

import pyotp

INTERVAL_SECONDS = 30
DIGITS = 6
VALID_WINDOW = 1  # aceita a janela anterior e a seguinte (atraso de relógio do celular)


def _totp(secret_b32: str) -> pyotp.TOTP:
    return pyotp.TOTP(secret_b32, digits=DIGITS, interval=INTERVAL_SECONDS)


def current_step(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // INTERVAL_SECONDS)


def code_at_step(secret_b32: str, step: int) -> str:
    return _totp(secret_b32).generate_otp(step)


def verify(secret_b32: str, code: str, last_step: int | None, now: float | None = None) -> int | None:
    """Valida `code`. Retorna o passo aceito ou None (inválido, fora da janela ou já usado)."""
    code = code.strip().replace(" ", "")
    if len(code) != DIGITS or not code.isdigit():
        return None
    agora = current_step(now)
    aceito = None
    # Compara todas as janelas, sem parar na primeira, para o tempo não depender de qual bateu.
    for step in range(agora - VALID_WINDOW, agora + VALID_WINDOW + 1):
        if hmac.compare_digest(code_at_step(secret_b32, step), code) and aceito is None:
            aceito = step
    if aceito is None or (last_step is not None and aceito <= last_step):
        return None
    return aceito
