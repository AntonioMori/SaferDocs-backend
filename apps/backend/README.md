# SaferDocs API

API REST do SaferDocs, sistema de assinatura digital de PDF. Feita em **Python 3.12 + FastAPI**, com **PostgreSQL** como banco.

## Arquitetura

Toda requisição atravessa as camadas de cima para baixo. As verificações que valem para todas as requisições ficam na entrada, num lugar só, e não espalhadas pelas rotas.

```
Entrada        ┌───────────────────────────────┐     ┌──────────────────────────────┐
               │ Middlewares                   │ ──► │ Rotas /api/v1                │
               │ CORS, headers, rate limit,    │     │ validação de entrada,        │
               │ CSRF, request id              │     │ erros padronizados, JWT      │
               └───────────────────────────────┘     └──────────────┬───────────────┘
Domínio        ┌────────────────────────────────────────────────────▼───────────────┐
               │ Serviços: autenticação, sessões, assinatura, verificação, auditoria │
               └──────────┬───────────────────────────┬──────────────────┬──────────┘
Infraestrutura ┌──────────▼──────────┐ ┌──────────────▼─────────┐ ┌──────▼──────────────┐
               │ Criptografia        │ │ Processamento do PDF   │ │ Persistência        │
               │ Argon2id, JWT,      │ │ pdf-worker isolado     │ │ PostgreSQL e        │
               │ AES-GCM, chaves     │ │ (sem rede/segredos)    │ │ migrações (Alembic) │
               └─────────────────────┘ └────────────────────────┘ └─────────────────────┘
```

| Pasta | Camada | Conteúdo |
|---|---|---|
| `app/middlewares/` | Entrada | CORS, cabeçalhos de segurança, rate limit, CSRF |
| `app/api/v1/routes/` | Entrada | Uma rota por domínio; valida a entrada e chama os serviços |
| `app/api/` | Entrada | Dependências compartilhadas (ex.: autenticação JWT) |
| `app/schemas/` | Entrada | Schemas Pydantic de entrada e saída |
| `app/services/` | Domínio | Regras do sistema |
| `app/crypto/` | Infraestrutura | Primitivas criptográficas |
| `app/pdf/` | Infraestrutura | Cliente do `pdf-worker`, que roda isolado em outro container |
| `app/db/` | Infraestrutura | Conexão, models e repositórios |
| `app/core/` | Transversal | Configuração, erros padronizados e logging |

As rotas não acessam o banco nem fazem criptografia diretamente: sempre passam por um serviço.

## Como executar

### Configuração (`.env`)
Todas as variáveis estão documentadas em [`.env.example`](.env.example). Para gerar um `.env` de desenvolvimento com segredos aleatórios (senha do banco, chaves do JWT, `MASTER_KEY` e `HASH_PEPPER`):
```bash
cd apps/backend
uv run python scripts/generate_env.py          # API dentro do Docker
uv run python scripts/generate_env.py --local  # API rodando fora do Docker
```
O `.env` nunca é commitado (está no `.gitignore`).

### Com Docker (recomendado)
Na raiz do repositório:
```bash
docker compose up --build
```
Sobe o PostgreSQL 16 e a API. A API só começa a atender depois de conectar no banco. Ela fica em `http://127.0.0.1:8000`; teste com `curl http://127.0.0.1:8000/api/v1/health`.

Se as portas 8000 ou 5432 já estiverem ocupadas na sua máquina, escolha outras:
```bash
API_HOST_PORT=8010 DB_HOST_PORT=55432 docker compose up --build
```

### Local, sem Docker
Requer [uv](https://docs.astral.sh/uv/) e Python 3.12.
```bash
cd apps/backend
uv sync
uv run uvicorn app.main:app --reload
```

## Versionamento da API

Todos os endpoints ficam sob **`/api/v1/`** (RNF-16). A versão só muda quando o contrato quebra para quem já usa a API (RNF-17).

| Mudança | Versão |
|---|---|
| Novo endpoint, novo campo **opcional** na entrada, novo campo na resposta, novo código de erro | Continua `v1` |
| Correção de bug que não altera o contrato | Continua `v1` |
| Remover ou renomear endpoint ou campo, tornar obrigatório um campo que era opcional, mudar o tipo ou o significado de um campo, mudar o formato do erro ou da autenticação | **Nova versão (`v2`)** |

Como uma nova versão entra: ela ganha o próprio pacote `app/api/v2/`, com um router de prefixo `/api/v2`, registrado em `app/main.py` ao lado do `v1`. As duas versões convivem até o frontend migrar; só então a `v1` é removida. Os serviços (`app/services/`) são compartilhados: o que muda entre versões é só a camada de rotas e schemas.

## Erros da API

Todo erro retorna o mesmo objeto JSON:
```json
{
  "code": "VAL_001",
  "message": "Dados inválidos.",
  "timestamp": "2026-11-23T14:00:00Z",
  "request_id": "6f1c…",
  "fields": [{ "field": "password", "reason": "mínimo de 12 caracteres" }]
}
```
`fields` só aparece em erros de validação. A resposta nunca traz stack trace, SQL ou o valor enviado. Os códigos seguem o padrão `DOMÍNIO_NNN` e vêm de um catálogo único (`app/core/errors.py`).

Uso dos status HTTP: **400** erro do cliente, **401** não autenticado, **403** autenticado mas sem permissão, **404** não encontrado, **405** método não permitido, **413** arquivo grande demais, **429** limite de requisições, **500** erro interno.

<!-- tabela-de-erros:inicio -->
| Código | Status | Mensagem |
|---|---|---|
| `AUTH_001` | 401 | E-mail ou senha inválidos. |
| `AUTH_002` | 401 | Código de verificação inválido. |
| `AUTH_003` | 401 | Autenticação necessária. |
| `AUTH_004` | 401 | Sessão encerrada. Faça login novamente. |
| `AUTH_005` | 401 | Sessão expirada. Faça login novamente. |
| `AUTH_006` | 400 | Não foi possível validar a passkey. |
| `AUTH_009` | 403 | Origem da requisição não permitida. |
| `AUTH_010` | 403 | Você não tem permissão para acessar este recurso. |
| `DOC_001` | 400 | O arquivo enviado não é um PDF. |
| `DOC_002` | 413 | O arquivo excede o tamanho máximo permitido. |
| `DOC_003` | 400 | PDFs com JavaScript embutido não são aceitos. |
| `DOC_004` | 400 | Não foi possível processar o PDF. |
| `DOC_005` | 400 | Página ou posição do selo inválida. |
| `VAL_001` | 400 | Dados inválidos. |
| `RES_001` | 404 | Recurso não encontrado. |
| `RES_002` | 405 | Método não permitido para este recurso. |
| `RATE_001` | 429 | Muitas requisições. Aguarde e tente novamente. |
| `SYS_001` | 500 | Erro interno. Tente novamente mais tarde. |
<!-- tabela-de-erros:fim -->

## Banco de dados e migrações

O schema é criado e alterado **somente** por migrations do Alembic (`alembic/versions/`). Nunca crie ou altere tabelas direto no banco.

```bash
cd apps/backend
uv run alembic upgrade head                            # aplica as migrations pendentes
uv run alembic revision --autogenerate -m "descrição"  # gera uma migration a partir dos models
uv run alembic downgrade -1                            # desfaz a última
```
No `docker compose up`, o container da API roda `alembic upgrade head` antes de subir.

Regras (verificadas pelos testes em `tests/test_migration_rules.py` e `tests/test_schema_sync.py`):
- **Nada de alteração manual:** o teste `test_schema_sync.py` aplica as migrations num banco limpo e compara com os models, como o `alembic check`. Model alterado sem migration, ou tabela criada à mão, faz o teste falhar.
- **Identificação:** o nome de cada arquivo começa com data e hora em UTC (`AAAAMMDD_HHMM_<revisão>_<descrição>.py`), gerado automaticamente pelo `alembic revision`.
- **Upgrade e downgrade:** toda migration implementa as duas funções; `downgrade()` desfaz exatamente o que `upgrade()` fez.
- **Trabalho em paralelo:** o histórico precisa ter uma única cabeça. Se duas pessoas criarem migrations ao mesmo tempo, antes do merge rode `uv run alembic heads` e, havendo duas, `uv run alembic merge heads -m "merge"`.

## Testes e lint
Os testes usam um PostgreSQL descartável (em memória, porta 55433), separado do banco de desenvolvimento:
```bash
docker compose --profile test up -d db-test   # na raiz do repositório
cd apps/backend
uv run pytest
uv run ruff check .
```
