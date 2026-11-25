"""Validação e sanitização de textos livres (REQ-64), como nome de usuário e de passkey.

Contra XSS: o texto é normalizado (NFKC, que transforma variantes "disfarçadas",
como letras de largura cheia, na forma comum) e recusado se tiver `<` ou `>`,
caracteres de controle ou caracteres invisíveis (inclusive os que invertem a
direção do texto, usados para enganar a leitura). Espaços repetidos viram um.
O front também escapa tudo ao exibir; esta é a defesa na entrada.

Contra injeção de SQL: a proteção é estrutural. Toda consulta passa pelo ORM
com parâmetros, e um teste (`tests/test_text_input.py`) varre o código e falha
se alguma consulta for montada concatenando texto. Por isso apóstrofos e
aspas, comuns em nomes ("D'Ávila"), são aceitos e gravados como vieram.
"""

import unicodedata

FORBIDDEN_CHARS = frozenset("<>")
# Controle (Cc), formato e invisíveis (Cf: inclui U+202E e o espaço de largura zero),
# uso privado (Co), surrogates (Cs) e não atribuídos (Cn).
FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Co", "Cs", "Cn"})


def clean_text(value: str, *, min_length: int, max_length: int) -> str:
    """Texto de uma linha, normalizado. Levanta ValueError (mensagem para o usuário) se não servir."""
    value = unicodedata.normalize("NFKC", value)
    if any(c in FORBIDDEN_CHARS for c in value):
        raise ValueError("os caracteres < e > não são permitidos")
    if any(unicodedata.category(c) in FORBIDDEN_CATEGORIES for c in value if c not in " "):
        raise ValueError("caracteres de controle ou invisíveis não são permitidos")
    value = " ".join(value.split())
    if len(value) < min_length:
        raise ValueError(f"mínimo de {min_length} caracteres")
    if len(value) > max_length:
        raise ValueError(f"máximo de {max_length} caracteres")
    return value
