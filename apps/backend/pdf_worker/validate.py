"""Recusa de PDF com JavaScript (REQ-63).

A varredura é estrutural, feita pelo parser (qpdf, via pikepdf), e não uma
busca de texto nos bytes do arquivo. Assim ela enxerga:

- nomes escritos com escape (`/J#53` é o mesmo nome que `/JS`);
- objetos guardados dentro de object streams comprimidos;
- objetos de um arquivo com tabela xref quebrada (o qpdf reconstrói);
- objetos que nenhuma página referencia (um leitor pode chegar neles por
  `/OpenAction`, `/Names` ou atualizações incrementais).

Um PDF é recusado se qualquer dicionário, em qualquer profundidade:
- tem a chave `/JS` ou `/JavaScript` (ações, árvore de nomes `/Names /JavaScript`);
- é uma ação `/S /JavaScript`;
- tem `/URI` ou `/Base` (base dos links relativos) com endereço `javascript:`,
  inclusive em UTF-16 com BOM, com BOM UTF-8 ou com caracteres invisíveis;
- tem a chave `/XFA`: formulários XFA carregam scripts próprios, fora do `/JS`.

Texto comum com a palavra "JavaScript" (no conteúdo da página ou numa string
como o título do documento) não é recusado: o que conta é a estrutura.

Falha fechada: se o qpdf avisar que não conseguiu montar algum objeto
(aninhamento além do limite, object stream que estoura a memória, objeto com
sintaxe quebrada), o objeto vira `null` e a varredura não teria como ver o
que havia nele. Nesse caso o PDF é recusado como não processável
(`DamagedPdfError`), em vez de passar como limpo.
"""

import io
import unicodedata

import pikepdf

# Avisos do qpdf que significam "um objeto se perdeu". Avisos de reparo comum
# (xref reconstruída, /Resources ausente) não entram: aparecem em PDFs limpos.
LOST_OBJECT_WARNINGS = (
    "limits error",
    "error decoding stream data",
    "bad_alloc",
    "unknown token",
    "parse error",
    "while reading token",
    "unexpected eof",
    "unexpected >",
    "unexpected )",
    "unexpected ]",
    "invalid character",
    "expected endobj",
    "expected n n obj",
)


class DamagedPdfError(Exception):
    """O qpdf descartou parte do documento: não dá para garantir que não há JavaScript."""


JAVASCRIPT_KEYS = frozenset({"/JS", "/JavaScript", "/XFA"})


def _is_javascript_dict(dictionary: pikepdf.Dictionary) -> bool:
    keys = set(dictionary.keys())
    if keys & JAVASCRIPT_KEYS:
        return True
    if dictionary.get("/S") == pikepdf.Name.JavaScript:
        return True
    # /URI de uma ação (ou de qualquer dicionário) e /Base do dicionário de URI do catálogo,
    # que serve de base para links relativos: nenhum dos dois pode ser javascript:.
    for key in ("/URI", "/Base"):
        value = dictionary.get(key)
        if isinstance(value, pikepdf.String) and _is_javascript_uri(value):
            return True
    return False


def _is_javascript_uri(uri: pikepdf.String) -> bool:
    """`javascript:` em qualquer forma: bytes crus, texto do PDF (UTF-16 com BOM), com BOM UTF-8."""
    raw = bytes(uri)
    candidates = [raw.decode("latin-1"), str(uri)]
    if raw.startswith(b"\xef\xbb\xbf"):  # BOM UTF-8
        candidates.append(raw[3:].decode("utf-8", errors="ignore"))
    for text in candidates:
        # Some com espaços, controles, BOM e caracteres invisíveis que os navegadores ignoram.
        cleaned = "".join(
            c for c in text if ord(c) > 0x20 and unicodedata.category(c) not in ("Cc", "Cf", "Zs")
        ).lower()
        if cleaned.startswith("javascript:"):
            return True
    return False


def _children(obj: pikepdf.Object) -> list[pikepdf.Object]:
    """Filhos diretos de um objeto. Objetos indiretos são visitados por conta própria."""
    if isinstance(obj, pikepdf.Stream):
        obj = obj.stream_dict
    if isinstance(obj, pikepdf.Dictionary):
        values = list(obj.values())
    elif isinstance(obj, pikepdf.Array):
        values = list(obj)
    else:
        return []
    return [
        v
        for v in values
        if isinstance(v, pikepdf.Dictionary | pikepdf.Array | pikepdf.Stream) and not v.is_indirect
    ]


def _contains_javascript(root: pikepdf.Object) -> bool:
    stack = [root]  # pilha explícita: um PDF com aninhamento enorme não estoura a recursão
    while stack:
        obj = stack.pop()
        dictionary = obj.stream_dict if isinstance(obj, pikepdf.Stream) else obj
        if isinstance(dictionary, pikepdf.Dictionary) and _is_javascript_dict(dictionary):
            return True
        stack.extend(_children(obj))
    return False


def _scan(document: pikepdf.Pdf) -> tuple[bool, list[str]]:
    """Varre o documento e devolve (achou JS?, avisos do qpdf).

    O `get_warnings()` do pikepdf entrega e LIMPA os avisos: quem precisar deles
    depois (ex.: o aviso de MediaBox reparado) usa a lista devolvida aqui.
    """
    found = _contains_javascript(document.trailer) or any(_contains_javascript(o) for o in document.objects)
    warnings = list(document.get_warnings())
    if not found and any(m in w.lower() for w in warnings for m in LOST_OBJECT_WARNINGS):
        raise DamagedPdfError()
    return found, warnings


def _without_startxref(pdf: bytes) -> bytes:
    """Cópia em que o qpdf não acha a xref e reconstrói a tabela varrendo o arquivo inteiro.

    A reconstrução enxerga objetos que estão no arquivo mas fora da xref atual
    (escondidos ou de uma revisão anterior). Um leitor que reconstrói a tabela,
    porque a xref "parece" quebrada, chegaria neles.
    """
    return pdf.replace(b"startxref", b"startxreX")


def has_javascript(document: pikepdf.Pdf) -> tuple[bool, list[str]]:
    """Procura JavaScript em todos os objetos e no trailer do documento aberto.

    Devolve também os avisos do qpdf até aqui. Levanta DamagedPdfError se ele perdeu algum objeto.
    """
    return _scan(document)


def has_javascript_in_rebuilt(pdf: bytes) -> bool:
    """Segunda passada, com a xref reconstruída (objetos fora da xref atual).

    Roda e fecha antes de o documento principal ser aberto, para nunca haver
    duas cópias do PDF abertas ao mesmo tempo dentro do limite de memória da tarefa.
    Se a cópia reconstruída nem abre, não há o que varrer: a passada normal decide.
    """
    try:
        rebuilt = pikepdf.open(io.BytesIO(_without_startxref(pdf)))
    except (pikepdf.PdfError, pikepdf.PasswordError, ValueError, OSError):
        return False
    with rebuilt:
        return _scan(rebuilt)[0]
