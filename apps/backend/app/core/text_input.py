"""Validação e sanitização de textos livres (REQ-64), como nome de usuário e de passkey.

Contra XSS: o texto é normalizado (NFKC, que transforma variantes "disfarçadas",
como letras de largura cheia, na forma comum) e recusado se tiver `<` ou `>`,
caracteres de controle ou caracteres invisíveis (inclusive os que invertem a
direção do texto, usados para enganar a leitura). Espaços repetidos viram um.
O front também escapa tudo ao exibir; esta é a defesa na entrada.

Também é recusado o que parece vazio: separadores de linha e de parágrafo
(U+2028, U+2029), caracteres de preenchimento que não desenham nada (U+115F,
U+1160, U+3164, U+FFA0, U+2800) e o texto sem nenhum caractere visível (letra,
número, pontuação ou símbolo). Assim o nome não vira um espaço em branco na tela.

Exceção para emoji: o U+200D (junta emoji, como em 👨‍👩‍👧) só passa entre dois emoji.
Qualquer outro caractere de formato (Cf) continua recusado.

Contra injeção de SQL: a proteção é estrutural. Toda consulta passa pelo ORM
com parâmetros, e um teste (`tests/test_text_input.py`) varre o código e falha
se alguma consulta for montada concatenando texto. Por isso apóstrofos e
aspas, comuns em nomes ("D'Ávila"), são aceitos e gravados como vieram.
"""

import unicodedata

FORBIDDEN_CHARS = frozenset("<>")
# Controle (Cc), formato e invisíveis (Cf: inclui U+202E e o espaço de largura zero),
# separadores de linha e de parágrafo (Zl, Zp), uso privado (Co), surrogates (Cs) e
# não atribuídos (Cn).
FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp", "Co", "Cs", "Cn"})
# Letras ou símbolos que não desenham nada (hangul de preenchimento, braille vazio).
FILLER_CHARS = frozenset("ᅟᅠㅤﾠ⠀")
VISIBLE_CATEGORY_PREFIXES = ("L", "N", "P", "S")

ZWJ = "‍"
VARIATION_SELECTOR_16 = "️"
SKIN_TONES = range(0x1F3FB, 0x1F400)


def _is_emoji(char: str) -> bool:
    return unicodedata.category(char) == "So" or ord(char) in SKIN_TONES


def _zwj_joins_emoji(value: str, index: int) -> bool:
    """O ZWJ em `index` está entre dois emoji (antes dele pode vir o seletor de variação VS16)."""
    if index + 1 >= len(value) or not _is_emoji(value[index + 1]):
        return False
    before = index - 1
    if before >= 1 and value[before] == VARIATION_SELECTOR_16:
        before -= 1
    return before >= 0 and _is_emoji(value[before])


def _has_forbidden_char(value: str) -> bool:
    for index, char in enumerate(value):
        if char == " ":
            continue
        if char in FILLER_CHARS:
            return True
        if unicodedata.category(char) not in FORBIDDEN_CATEGORIES:
            continue
        if char == ZWJ and _zwj_joins_emoji(value, index):
            continue
        return True
    return False


def clean_text(value: str, *, min_length: int, max_length: int) -> str:
    """Texto de uma linha, normalizado. Levanta ValueError (mensagem para o usuário) se não servir."""
    value = unicodedata.normalize("NFKC", value)
    if any(c in FORBIDDEN_CHARS for c in value):
        raise ValueError("os caracteres < e > não são permitidos")
    if _has_forbidden_char(value):
        raise ValueError("caracteres de controle ou invisíveis não são permitidos")
    value = " ".join(value.split())
    if len(value) < min_length:
        raise ValueError(f"mínimo de {min_length} caracteres")
    if not any(unicodedata.category(c).startswith(VISIBLE_CATEGORY_PREFIXES) for c in value):
        raise ValueError("precisa ter ao menos um caractere visível")
    if len(value) > max_length:
        raise ValueError(f"máximo de {max_length} caracteres")
    return value
