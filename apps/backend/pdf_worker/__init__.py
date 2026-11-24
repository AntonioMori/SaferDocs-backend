"""pdf-worker: todo parsing de PDF roda aqui, isolado da API (REQ-62).

Roda num container próprio, sem rede, sem segredos, só leitura e sem
privilégios. A API conversa com ele por um socket Unix num volume
compartilhado (ver `protocol.py`). Cada requisição é tratada num processo
novo, com limite de tempo, memória e arquivos (`server.py`): um PDF que
explore um bug do parser derruba só esse processo.

Este `__init__` não importa nada de propósito: a API importa só
`pdf_worker.protocol`, e o pikepdf existe apenas na imagem do worker.
"""
