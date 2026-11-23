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

### Com Docker (recomendado)
Na raiz do repositório:
```bash
docker compose up --build
```
A API sobe em `http://localhost:8000`. Teste: `curl http://localhost:8000/api/v1/health`.

### Local, sem Docker
Requer [uv](https://docs.astral.sh/uv/) e Python 3.12.
```bash
cd apps/backend
uv sync
uv run uvicorn app.main:app --reload
```

## Testes e lint
```bash
cd apps/backend
uv run pytest
uv run ruff check .
```
