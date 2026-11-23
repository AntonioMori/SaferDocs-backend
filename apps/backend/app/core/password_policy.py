"""Política de senhas (REQ-01).

Mínimo de 12 caracteres, com letras maiúsculas, minúsculas, números e
símbolos. O máximo de 128 limita o custo do Argon2 contra abuso.
Usada no cadastro e na troca de senha.
"""

MIN_LENGTH = 12
MAX_LENGTH = 128


def password_policy_violations(password: str) -> list[str]:
    """Lista as regras que a senha não cumpre (vazia = senha aceita)."""
    violations = []
    if len(password) < MIN_LENGTH:
        violations.append(f"mínimo de {MIN_LENGTH} caracteres")
    if len(password) > MAX_LENGTH:
        violations.append(f"máximo de {MAX_LENGTH} caracteres")
    if not any(c.isupper() for c in password):
        violations.append("ao menos uma letra maiúscula")
    if not any(c.islower() for c in password):
        violations.append("ao menos uma letra minúscula")
    if not any(c.isdigit() for c in password):
        violations.append("ao menos um número")
    if not any(not c.isalnum() and not c.isspace() for c in password):
        violations.append("ao menos um símbolo")
    return violations
