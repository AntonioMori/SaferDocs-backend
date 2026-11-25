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

- **Origens (REQ-31):** só as de `CORS_ALLOWED_ORIGINS`, comparadas por igualdade exata. Na inicialização cada origem é normalizada para o formato que o navegador envia no `Origin`: esquema e host em minúsculas, sem barra no fim e sem a porta padrão (`HTTPS://App.ts.net:443/` vira `https://app.ts.net`). Host internacional vira punycode (`bücher` vira `xn--bcher-kva`) e IPs ficam na forma canônica. Origens repetidas depois de normalizar são removidas. É recusada, com erro na inicialização, toda origem que nenhum navegador enviaria: com caminho, query, fragmento, usuário e senha, espaço, porta 0 ou vazia, host inválido ou IP abreviado como `127.1`. Só o middleware decide CORS: se uma rota puser `Access-Control-*` por conta própria (até `*`), esses headers são descartados. A resposta traz `Access-Control-Allow-Origin` com a própria origem, nunca `*` (o `*` já é recusado na inicialização), e `Vary: Origin` (este vai em toda resposta, inclusive sem `Origin`, porque a mesma URL responde diferente conforme a origem). Origem fora da lista não recebe nenhum header CORS, e o navegador bloqueia a leitura da resposta.
- **Preflight (REQ-35):** `OPTIONS` com `Access-Control-Request-Method` é respondida pelo próprio middleware, com 204 e sem corpo, antes de rate limit, CSRF e autenticação. A resposta traz `Access-Control-Allow-Origin`, `Access-Control-Allow-Methods` e `Access-Control-Allow-Headers`. Preflight de origem fora da lista recebe 403 `AUTH_009`, sem nenhum header CORS. Headers repetidos não enganam a checagem: `Origin` ou `Access-Control-Request-Method` em mais de uma linha são recusados, e várias linhas de `Access-Control-Request-Headers` são conferidas juntas, como uma lista só.
- **Métodos (REQ-32):** só `GET`, `POST`, `PUT`, `DELETE` e `OPTIONS`. Preflight pedindo outro método (como `PATCH`) recebe 403 `AUTH_009`, sem headers CORS.
- **Headers (REQ-33):** só `Authorization`, `Content-Type` e `X-Request-ID`, sem diferenciar maiúsculas. Preflight pedindo qualquer outro header também recebe 403. Por isso o CSRF (REQ-65) é verificado pelo `Origin`/`Referer`, e não por um header de token.
- **Credenciais (REQ-34):** `Access-Control-Allow-Credentials: true` (necessário para o cookie de refresh) vai só para as origens da lista, inclusive na preflight. Origem fora da lista, ou preflight recusada, não recebe esse header. Este é o motivo da implementação própria: o `CORSMiddleware` do Starlette envia o header de credenciais para qualquer origem. As origens permitidas também podem ler `X-Request-ID` e `Retry-After` (`Access-Control-Expose-Headers`).
- **Cache da preflight (REQ-36):** a preflight aceita traz `Access-Control-Max-Age` com o valor de `CORS_MAX_AGE_SECONDS` (padrão 600 s), e o navegador não repete a preflight nesse intervalo.

Em desenvolvimento e no deploy, o front e a API ficam na mesma origem (proxy do Vite ou nginx), então o navegador nem chega a usar CORS. As regras acima valem para qualquer outra origem que tente chamar a API.

## Cabeçalhos de segurança (REQ-37 a 44)

`app/middlewares/security_headers.py` coloca os headers abaixo em **toda** resposta da API: sucesso, erro, rota inexistente e preflight. Os valores são fixos no código, e nenhuma variável de ambiente consegue enfraquecê-los. Eles também sobrescrevem o que uma rota tenha posto, sem duplicar: é uma decisão de projeto, para nenhuma rota conseguir enfraquecê-los. Se um dia uma rota precisar de um valor *mais* estrito (ex.: CSP `sandbox` no download do PDF), isso vira uma exceção explícita no middleware. Ordem dos middlewares, de fora para dentro: `request_id -> security_headers -> CORS -> unhandled_errors -> rotas`.

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

## Rate limiting (REQ-05 e 53)

`app/middlewares/rate_limit.py` limita requisições numa janela deslizante em memória, por escopo e chave. Ao estourar, a resposta é 429 `RATE_001` com `Retry-After`, que o front consegue ler (o header está exposto no CORS).

| Onde | Chave | Limite (`.env`) |
|---|---|---|
| `POST /auth/login` | IP | `RATE_LIMIT_LOGIN_PER_IP` (10/min) |
| `POST /auth/login` | e-mail normalizado (minúsculas, sem espaços) | `RATE_LIMIT_LOGIN_PER_ACCOUNT` (5/min) |
| `POST /auth/login/totp` | IP | `RATE_LIMIT_LOGIN_PER_IP` |
| `POST /verify` | IP | `RATE_LIMIT_VERIFY_PER_IP` (10/min) |

- O limite roda antes de qualquer consulta ou hash de senha: força bruta não vira negação de serviço por CPU.
- A conta que não existe tem o mesmo limite da que existe, então o 429 não revela nada (REQ-04).
- Requisição recusada não conta: quem insiste não estende o próprio bloqueio.
- Com os valores padrão, o limite por conta (5/min) e o bloqueio da conta (REQ-03, 5 falhas) atuam juntos: depois da 5ª falha a conta fica bloqueada por 15 min, e a 6ª tentativa no mesmo minuto já recebe 429.
- O estado fica em memória, porque a API roda num processo só. O total de chaves é limitado a 100 mil, para quem troca de IP ou de e-mail a cada pedido não esgotar a memória. Com mais de um processo, o contador precisaria ir para o PostgreSQL ou um Redis.
- O IP é o da conexão TCP (`request.client.host`), não um header que o cliente controle. Atrás de um proxy reverso, o uvicorn precisa de `--forwarded-allow-ips` só com o IP do proxy; senão todo mundo aparece com o IP do proxy e divide o mesmo limite.

## Upload e processamento de PDF (REQ-60 a 63)

Todo PDF passa pelos filtros na ordem da Figura 9 do enunciado. Os dois primeiros ficam na API e não abrem o arquivo. Os de parsing ficam no worker isolado.

- **Leitura do upload (REQ-61):** `app/pdf/upload.py` lê o `multipart/form-data` em streaming, direto da conexão e só em memória. O `UploadFile` do FastAPI não é usado porque grava em arquivo temporário todo upload acima de 1 MB, e o PDF não pode ir para o disco (seção 9.2). Um `Content-Length` acima de `MAX_UPLOAD_MB` é recusado sem ler o corpo. Sem `Content-Length`, ou com um valor falso, a leitura para no primeiro byte acima do limite. Os dois casos dão 413 `DOC_002`. O formato é fechado: um único arquivo no campo `file` e só os campos de texto que a rota declarar, cada um com no máximo 256 bytes e uma vez só. As rotas usam a dependência `pdf_upload_with("page", "x", "y")`. Todo erro de upload responde com `Connection: close`: sem isso o uvicorn continuaria lendo e descartando o resto do corpo para manter o keep-alive (o QA mandou cerca de 10 GB numa conexão depois do 413; agora ela cai na hora). A leitura tem prazo, já que o uvicorn não limita o tempo do corpo: 15 s sem chegar nada ou 5 min no total encerram o envio. Os avisos do python-multipart, que citam bytes do corpo, ficam fora do log, e nomes de campo estranhos não voltam na resposta de erro. O prazo dos cabeçalhos (slowloris antes do corpo) depende do proxy na frente da API, no deploy.
- **Magic number (REQ-60):** o arquivo precisa começar exatamente com `%PDF-`. A conferência é feita assim que chegam os 5 primeiros bytes, mesmo divididos entre pedaços da rede. Um executável renomeado para `.pdf` é recusado com 400 `DOC_001` depois de ler só o primeiro pedaço. O nome do arquivo e o `Content-Type` da parte são ignorados, porque o cliente controla os dois.
- **Processamento isolado (REQ-62):** todo parsing de PDF acontece no `pdf-worker` (`pdf_worker/`), um container separado. A API nem tem uma biblioteca de PDF instalada: o `pikepdf` existe só na imagem do worker e nos testes. As duas imagens conversam por um socket Unix no volume `pdfsock`, usando o protocolo de `pdf_worker/protocol.py`, com timeout de `PDF_WORKER_TIMEOUT_SECONDS`.

  | Camada | Proteção |
  |---|---|
  | Container (`docker-compose.yml`) | `network_mode: none` (só `lo`), raiz `read_only`, `cap_drop: ALL`, `no-new-privileges`, usuário 10001, `mem_limit` 512 MB, `cpus` 1, `pids_limit` 64. Não usa o `.env`, então não há nenhum segredo no ambiente |
  | Socket | Modo `0660`, dono e grupo 10001, diretório `0750`. A API entra no grupo (`group_add`) e monta o volume só leitura. Outro container sem o grupo não consegue conectar |
  | Pedido | No máximo 2 pedidos em atendimento: a vaga é pega **antes** de ler o PDF, então no máximo 2 PDFs ficam em memória. Quem espera mais de 5 s na fila recebe `BUSY` (a API responde 429 com `Retry-After`). O servidor confere os tamanhos declarados antes de alocar (cabeçalho até 512 KB, corpo até 128 MB) e recusa lixo com `BAD_REQUEST` |
  | Tarefa | Cada pedido roda num processo novo (`python -m pdf_worker.task`) com tempo de CPU e de relógio de 15 s, memória de 256 MB (um `inspect` de 20 MB usa cerca de 110 MB), `RLIMIT_FSIZE` 0 (não grava nenhum byte em arquivo), até 32 descritores, `RLIMIT_NPROC` 0 (não cria processos nem threads, então um exploit não sobrevive ao fim da tarefa) e sem core dump. O container roda com `init: true`, que recolhe processos órfãos. Se o parser travar ou cair com um PDF malicioso, morre só esse processo (`TIMEOUT` ou `UNPROCESSABLE`) |

  Hoje o worker tem a operação `inspect`, que abre o PDF e devolve as páginas e seus tamanhos. O tamanho vem do `/MediaBox` da página ou dos ancestrais; se ele faltar ou for inválido (o qpdf trocaria por 612x792 só com um aviso), o PDF é recusado, porque um tamanho inventado poria o selo no lugar errado. Quando o worker responde `BUSY`, ele ainda lê e descarta o que o cliente está enviando, por até 5 s, para o cliente conseguir ler a resposta; o cliente da API também lê a resposta mesmo se o envio quebrar. `prepare_sign`, `finish_sign` e `verify` já passam pelo `inspect` no worker e ganham a lógica real com o REQ-46 e o REQ-50. Erros viram `DOC_004` (PDF corrompido, com senha ou que estoura tempo ou memória), `DOC_003` (JavaScript) e `DOC_005` (posição do selo). Com o worker ocupado, a resposta é 429 `RATE_001` com `Retry-After: 5`; fora do ar, 500 `SYS_001`. Os tempos do worker (fila 5 s + leitura 5 s + tarefa 15 s) somam menos que o `PDF_WORKER_TIMEOUT_SECONDS` da API (30 s), então a API sempre recebe uma resposta do worker. As funções do cliente são síncronas: numa rota `async def`, chame com `await run_in_threadpool(...)`.

- **PDF com JavaScript (REQ-63):** toda operação do worker começa em `open_pdf`, que abre o documento e roda `pdf_worker/validate.py`. A varredura é feita pelo parser (qpdf) e não por busca de texto nos bytes. Assim ela pega nomes com escape (`/J#53` é `/JS`), objetos dentro de object streams comprimidos, xref quebrada, objetos órfãos e atualizações incrementais. É recusado, com 400 `DOC_003`, o PDF em que qualquer dicionário, em qualquer profundidade, tenha a chave `/JS`, `/JavaScript` ou `/XFA` (formulário XFA, que carrega scripts próprios), seja uma ação `/S /JavaScript` ou tenha `/URI` ou `/Base` com endereço `javascript:` (inclusive em UTF-16 com BOM, com BOM UTF-8 ou com caracteres invisíveis). A varredura **falha fechada**: se o qpdf avisar que perdeu um objeto (aninhamento além do limite, object stream que estoura a memória, sintaxe quebrada), o PDF é recusado com `DOC_004`, porque não dá para garantir que não havia JavaScript ali. Há também uma segunda passada com a xref reconstruída, que acha objetos presentes no arquivo mas fora da xref atual. Ela roda e é fechada antes de o documento principal abrir, para não dobrar a memória. A palavra "JavaScript" no texto da página ou numa string não é recusada, porque o que conta é a estrutura. Como `prepare_sign` e `verify` passam pelo worker, a recusa vale na assinatura e na verificação.

  O Windows não tem socket Unix, então a API que usa o worker roda pelo `docker compose`. Nos testes, a fixture `fake_pdf_worker` liga o cliente ao código real do worker por um par de sockets em memória. Os testes do servidor, que dependem de Linux (socket Unix e limites do sistema), rodam num container com o mesmo isolamento:
  ```bash
  docker compose --profile test run --rm worker-tests
  ```

## Assinatura de documentos (REQ-45 a 49 e REQ-59)

**Chaves (REQ-45):** no cadastro, cada usuário ganha um par ECDSA P-256 e um certificado X.509 autoassinado com o nome dele (`app/services/user_keys.py`). A privada fica em PKCS#8, cifrada com AES-256-GCM numa chave derivada da `MASTER_KEY` só para isso, com o id do usuário como dado associado. Uma conta criada antes disso ganha o par na primeira assinatura.

**Assinatura embutida (REQ-46):** `POST /api/v1/documents/sign` (autenticado; multipart com `file`, `page`, `x`, `y`) devolve o PDF assinado (`application/pdf`), com o id da assinatura no header `X-Signature-Id`. A assinatura segue o PDF Signature da ISO 32000: um campo de assinatura com aparência (o selo) e um CMS `adbe.pkcs7.detached` que cobre o arquivo inteiro pelo `/ByteRange`. O fluxo tem três etapas, e a chave privada nunca entra no worker:

1. o worker (`pdf_worker/sign.py`, pyHanko) desenha o selo, reserva o `/Contents` e devolve o SHA-256 dos bytes cobertos;
2. a API (`app/crypto/cms.py`, só asn1crypto e cryptography) monta o CMS com esse digest e assina os atributos com a chave do usuário;
3. o worker escreve o CMS no espaço reservado.

**Selo (REQ-47):** o selo visual (240 x 80 pt) mostra o nome de quem assinou, a data e a hora em UTC, o SHA-256 completo do documento original (em duas linhas) e o id da assinatura, que é gerado antes de o selo ser desenhado. Nome longo é cortado com "..." e caracteres fora do WinAnsi (a fonte padrão do selo) viram "?".

**Registro (REQ-48):** cada assinatura grava em `signatures` o SHA-256 do original e do assinado, o usuário, a data e hora (a mesma do selo), o IP, o User-Agent e a posição do selo, e vai para a auditoria como `DOCUMENT_SIGNED` (falhas também, com o código do erro). O PDF só volta para o usuário depois do commit. `GET /api/v1/documents/signatures` lista as assinaturas do próprio usuário, só com metadados e hashes.

**Posição (REQ-49):** `page` começa em 1; `x` e `y` são o canto inferior esquerdo do selo, em pontos PDF (1/72 de polegada), contados a partir do canto inferior esquerdo da página, mesmo quando o `/MediaBox` não começa em (0, 0). O selo inteiro (240 x 80) precisa caber na página escolhida; página inexistente ou selo saindo da página dão 400 `DOC_005`. A posição fica registrada com a assinatura.

**Chave privada nunca exposta (REQ-59):** a privada decifrada só existe dentro de `sign_with_user_key`, num invólucro (`Redacted`) que mostra `<oculto>` em repr, str, f-string e log e não pode ir para pickle. Ela não vai para o worker, para a resposta nem para o log. Os schemas de resposta não têm campo de chave, e falha ao decifrar vira um 500 genérico. Um teste percorre o fluxo inteiro (cadastro, login, assinatura, histórico, erros) com o log em DEBUG e procura a chave em DER, PEM, hex, base64, o escalar e o texto cifrado.

A autenticação roda antes de ler o upload. Se o leitor do pyHanko recusar o arquivo (por exemplo, xref ausente que o qpdf consegue reconstruir), o worker assina a versão regravada pelo qpdf.

## Testes e lint
Os testes usam um PostgreSQL descartável (em memória, porta 55433), separado do banco de desenvolvimento:
```bash
docker compose --profile test up -d db-test   # na raiz do repositório
cd apps/backend
uv run pytest
uv run ruff check .
```
