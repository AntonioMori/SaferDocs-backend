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

## Banco de dados e migrações

O schema é criado e alterado **somente** por migrations do Alembic (`alembic/versions/`). Nunca crie ou altere tabelas direto no banco.

```bash
cd apps/backend
uv run alembic upgrade head                            # aplica as migrations pendentes
uv run alembic revision --autogenerate -m "descrição"  # gera uma migration a partir dos models
uv run alembic downgrade -1                            # desfaz a última
```
No `docker compose up`, o container da API roda `alembic upgrade head` antes de subir.

## Testes e lint
Os testes usam um PostgreSQL descartável (em memória, porta 55433), separado do banco de desenvolvimento:
```bash
docker compose --profile test up -d db-test   # na raiz do repositório
cd apps/backend
uv run pytest
uv run ruff check .
```
