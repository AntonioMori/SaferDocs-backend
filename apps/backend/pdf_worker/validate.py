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
- é uma ação `/S /URI` com endereço `javascript:`;
- tem a chave `/XFA`: formulários XFA carregam scripts próprios, fora do `/JS`.

Texto comum com a palavra "JavaScript" (no conteúdo da página ou numa string
como o título do documento) não é recusado: o que conta é a estrutura.
"""

import pikepdf

JAVASCRIPT_KEYS = frozenset({"/JS", "/JavaScript", "/XFA"})


def _is_javascript_dict(dictionary: pikepdf.Dictionary) -> bool:
    keys = set(dictionary.keys())
    if keys & JAVASCRIPT_KEYS:
        return True
    action = dictionary.get("/S")
    if action == pikepdf.Name.JavaScript:
        return True
    if action == pikepdf.Name.URI:
        uri = dictionary.get("/URI")
        if isinstance(uri, pikepdf.String):
            # Remove espaços e controles que os navegadores ignoram antes do esquema.
            text = bytes(uri).decode("latin-1")
            cleaned = "".join(c for c in text if ord(c) > 0x20).lower()
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


def has_javascript(document: pikepdf.Pdf) -> bool:
    """Procura JavaScript em todos os objetos do documento e no trailer."""
    if _contains_javascript(document.trailer):
        return True
    return any(_contains_javascript(obj) for obj in document.objects)
