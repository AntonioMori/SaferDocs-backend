# SaferDocs API

API REST do SaferDocs, sistema de assinatura digital de PDF. Feita em **Python 3.12 + FastAPI**, com **PostgreSQL** como banco.

## Backend e frontend desacoplados

Este repositório contém **só a API**. O frontend (React + Vite) é outra aplicação, em outro repositório (`SaferDocs-frontend`), e conversa com o backend **exclusivamente** pelos endpoints HTTP em `/api/v1`. O backend não renderiza HTML nem serve os arquivos do frontend; toda regra de negócio e de segurança fica aqui. As duas aplicações sobem, são testadas e são publicadas de forma independente.

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

### Interfaces entre os módulos

Os módulos se comunicam por estas funções. Algumas começaram como *stub* (assinatura final, comportamento provisório) para que cada parte pudesse ser desenvolvida em paralelo. O cabeçalho de cada arquivo diz se ainda é stub e qual requisito traz a implementação real.

| Interface | Arquivo | Uso |
|---|---|---|
| `get_current_user` / `CurrentUser` | `app/api/deps.py` | Dependência de toda rota autenticada |
| `issue_tokens(db, user, request, response)` | `app/services/token_service.py` | Fim de qualquer login (senha + TOTP, passkey, refresh) |
| `audit.record(db, action=..., result=..., request=..., user_id=..., details=...)` | `app/services/audit_service.py` | Log de auditoria append-only (grava na transação de quem chama) |
| `security_events.emit(db, user_id=..., type=..., request=...)` | `app/services/security_events.py` | Atividade de segurança mostrada ao usuário |
| `check_rate_limit(scope, key, limit)` / `limit_by_ip(scope, limit)` | `app/middlewares/rate_limit.py` | Rate limit por conta ou por IP |
| `generate_user_keys(db, user)` | `app/services/user_keys.py` | Par de chaves de assinatura no cadastro |
| `prepare_sign` / `finish_sign` / `verify` | `app/pdf/client.py` | Operações no pdf-worker isolado |
| `encrypt` / `decrypt(AeadContext, ...)` | `app/crypto/aead.py` | AES-256-GCM com chave derivada por contexto |

Para chamar rotas protegidas em desenvolvimento antes do login real existir:
```bash
TOKEN=$(uv run python scripts/dev_token.py --user-agent dev)
curl -A dev -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/api/v1/...
```
O token só vale com o mesmo User-Agent da sessão (REQ-27), por isso o `-A dev`.

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

## Verificação em duas etapas (REQ-11 a 16)

TOTP da RFC 6238 (30 s, 6 dígitos, tolerância de ±1 janela), compatível com Google Authenticator e Authy. O passo de tempo aceito fica em `users.totp_last_step`, então o mesmo código não vale duas vezes. O segredo tem 160 bits e fica cifrado com AES-256-GCM (chave derivada da `MASTER_KEY`, id do usuário como dado associado).

| Rota | Corpo | Resposta |
|---|---|---|
| `POST /auth/2fa/setup` | n/a | `{otpauth_uri, secret}`: o front gera o QR Code a partir da URI. Ainda não ativa |
| `POST /auth/2fa/enable` | `{code}` | `{recovery_codes}`: ativa e mostra os 10 códigos de recuperação uma única vez |
| `POST /auth/2fa/disable` | `{password, code}` | 204 |
| `POST /auth/2fa/recovery-codes` | `{code}` | `{recovery_codes}`: conjunto novo, os antigos deixam de valer |
| `POST /auth/login` | `{email, password}` | Com 2FA ativo: `{mfa_required: true, mfa_token, expires_in}`, sem JWT nem cookie |
| `POST /auth/login/totp` | `{mfa_token, code}` ou `{mfa_token, recovery_code}` | `{access_token, user, ...}` + cookie |

O `mfa_token` é opaco, vale 5 minutos e só uma vez, e no banco fica só o hash. Códigos errados contam para o bloqueio da conta (REQ-03) e vão para a auditoria como `TOTP_FAILURE`. Com 3 falhas em 15 minutos, o usuário recebe um alerta `TOTP_FAILURES` na atividade de segurança.

## Log de auditoria (REQ-55 e 56)

`audit.record(...)` grava na tabela `audit_log`, que só aceita inserção. São registrados login, logout, falha de autenticação, emissão de token, troca de senha, assinatura e verificação, além de outros eventos de segurança (bloqueio de conta, reuso de refresh, sessões encerradas).

A imutabilidade tem duas barreiras independentes, criadas pela migration `208d8c8cdcb5`:
- **Triggers:** `UPDATE`, `DELETE` e `TRUNCATE` no `audit_log` falham com `audit_log é append-only`, inclusive para o dono da tabela e para superusuários.
- **Permissões:** o papel `saferdocs_app` tem acesso normal às demais tabelas, mas só `SELECT` e `INSERT` no `audit_log`.

Campos de cada registro (REQ-56), garantidos pelo serviço e por `NOT NULL`/`CHECK` no banco: horário UTC, IP, User-Agent, ação e resultado (`SUCCESS` ou `FAILURE`). O `user_id` só pode faltar em `AUTH_FAILURE` (e-mail inexistente) e `DOCUMENT_VERIFIED` (verificação pública). Sem requisição, IP e User-Agent ficam `desconhecido`. O `details` (JSONB) é opcional e passa por um filtro: chaves com nome sensível (senha, token, chave, código, PDF...) e valores binários viram `[removido]`.

Em produção, a API deve conectar com um usuário membro desse papel, e só as migrations usam o dono do banco:
```sql
CREATE ROLE saferdocs_api LOGIN PASSWORD '<senha forte>' IN ROLE saferdocs_app;
```

### Atividade de segurança (REQ-58)

Eventos que o próprio usuário precisa ver ficam em `security_events`, separados do audit log porque precisam do campo "visto": login de IP desconhecido, troca de senha, ativação e desativação do 2FA, reuso de refresh token e mudança de IP durante a sessão. O IP de login é comparado pelo HMAC com os já usados pela conta (`known_ips`); o IP do cadastro já conta como conhecido.

| Rota | Efeito |
|---|---|
| `GET /api/v1/security/events` | Até 100 eventos, os não vistos primeiro: `{id, type, created_at, seen, details}` |
| `POST /api/v1/security/events/seen` | `{ids: [...]}` marca como vistos; ids de outra conta são ignorados |

O login e o refresh devolvem `unseen_security_events`, para o front destacar os eventos não vistos logo após entrar.

## CORS (REQ-31 a 36)

`app/middlewares/cors.py` é uma implementação própria, para que nenhuma origem fora da lista receba header CORS algum.

- **Origens (REQ-31):** só as de `CORS_ALLOWED_ORIGINS`, comparadas por igualdade exata. A resposta traz `Access-Control-Allow-Origin` com a própria origem, nunca `*` (o `*` já é recusado na inicialização), e `Vary: Origin`. Origem fora da lista não recebe nenhum header CORS, e o navegador bloqueia a leitura da resposta.
- **Preflight (REQ-35):** `OPTIONS` com `Access-Control-Request-Method` é respondida pelo próprio middleware, com 204 e sem corpo, antes de rate limit, CSRF e autenticação. A resposta traz `Access-Control-Allow-Origin`, `Access-Control-Allow-Methods` e `Access-Control-Allow-Headers`. Preflight de origem fora da lista recebe 403 `AUTH_009`, sem nenhum header CORS.
- **Métodos (REQ-32):** só `GET`, `POST`, `PUT`, `DELETE` e `OPTIONS`. Preflight pedindo outro método (como `PATCH`) recebe 403 `AUTH_009`, sem headers CORS.
- **Headers (REQ-33):** só `Authorization`, `Content-Type` e `X-Request-ID`, sem diferenciar maiúsculas. Preflight pedindo qualquer outro header também recebe 403. Por isso o CSRF (REQ-65) é verificado pelo `Origin`/`Referer`, e não por um header de token.
- **Credenciais (REQ-34):** `Access-Control-Allow-Credentials: true` (necessário para o cookie de refresh) vai só para as origens da lista, inclusive na preflight. Origem fora da lista, ou preflight recusada, não recebe esse header. Este é o motivo da implementação própria: o `CORSMiddleware` do Starlette envia o header de credenciais para qualquer origem. As origens permitidas também podem ler `X-Request-ID` e `Retry-After` (`Access-Control-Expose-Headers`).
- **Cache da preflight (REQ-36):** a preflight aceita traz `Access-Control-Max-Age` com o valor de `CORS_MAX_AGE_SECONDS` (padrão 600 s), e o navegador não repete a preflight nesse intervalo.

Em desenvolvimento e no deploy, o front e a API ficam na mesma origem (proxy do Vite ou nginx), então o navegador nem chega a usar CORS. As regras acima valem para qualquer outra origem que tente chamar a API.

## Cabeçalhos de segurança (REQ-37 a 44)

`app/middlewares/security_headers.py` coloca os headers abaixo em **toda** resposta da API: sucesso, erro, rota inexistente e preflight. Os valores são fixos no código, e nenhuma variável de ambiente consegue enfraquecê-los. Ordem dos middlewares, de fora para dentro: `request_id -> security_headers -> CORS -> unhandled_errors -> rotas`.

O `unhandled_errors` é o mais interno porque o handler de `Exception` do FastAPI roda por fora de todos os middlewares. Sem ele, um erro 500 sairia sem os headers de segurança, sem CORS e sem `X-Request-ID`. Ele captura a exceção, registra o detalhe só no log e devolve o `SYS_001` padronizado por dentro da cadeia.

| Header | Valor | Requisito |
|---|---|---|
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'` | REQ-37 |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` | REQ-38 |
| `X-Frame-Options` | `DENY` | REQ-39 |
| `X-Content-Type-Options` | `nosniff` | REQ-40 |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | REQ-41 |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` | REQ-42 |
| `Cache-Control` | `no-store` | REQ-43 |
| `X-XSS-Protection` | `0` | REQ-44 |

O `Cache-Control: no-store` (REQ-43) vale para toda a API, e não só para as rotas que exigem JWT. Login, refresh e TOTP também devolvem tokens, e o PDF assinado é um documento. Aplicar em tudo evita que uma rota nova fique de fora por esquecimento.

Conferir com `curl -I http://localhost:8000/api/v1/health`.

## Testes e lint
Os testes usam um PostgreSQL descartável (em memória, porta 55433), separado do banco de desenvolvimento:
```bash
docker compose --profile test up -d db-test   # na raiz do repositório
cd apps/backend
uv run pytest
uv run ruff check .
```
