# Guia de Contribuição: SaferDocs

Projeto 3 de Segurança da Informação (UAB00084/UFRPE). Este repositório contém **apenas o backend (API REST em FastAPI)** do SaferDocs. O frontend (React + Vite + Minimals) fica em `AntonioMori/SaferDocs-frontend`.

## 1. Fluxo de trabalho (exigência da disciplina)

1. **Toda tarefa é uma issue** com o código do requisito no título (`REQ-01 Política de senhas`, `RNF-05 Configuração em .env`), um label e um responsável. Ela começa na coluna **Todo** do GitHub Project deste repositório.
2. Ao começar, mova o card para **In progress** e crie **uma branch por issue** a partir da `main` atualizada:
   ```bash
   git checkout main && git pull
   git checkout -b feat/12-req-01-politica-senhas
   ```
   Prefixos: `feat/` (funcionalidade), `fix/` (correção), `chore/` (configuração e limpeza), `docs/` (documentação), `test/` (testes).
3. **Commits** no formato `tipo: descrição curta`, terminando com a referência à issue:
   ```
   feat: valida política de senhas no cadastro

   Ref #12
   ```
   Tipos: `feat`, `fix`, `chore`, `docs`, `refactor`, `test`, `style`. Evite mensagens como `ajustes`, `wip` e `final`.
4. Abra um **Pull Request para a `main`**, com `Closes #<id>` na descrição, e faça o **merge**. O card vai para **Done**.
5. Um requisito com parte no backend e parte no frontend tem **uma issue em cada repositório**. Cada commit referencia a issue do próprio repo.

## 2. Regras de segurança do repositório

- **Nunca** commitar `.env`, chaves (`*.pem`, `*.key`) ou credenciais. As variáveis ficam documentadas no `.env.example`.
- Toda mudança de schema do banco passa por uma migration do Alembic (RNF-09/10). Antes do merge, confira `alembic heads`.
- Dependências são verificadas automaticamente no CI (REQ-66). Não ignore alertas de vulnerabilidade.

## 3. Estrutura

| Diretório | Conteúdo |
| :--- | :--- |
| `apps/backend/` | API REST (FastAPI), serviços, criptografia e migrações |
| `docker-compose.yml` | PostgreSQL e backend para desenvolvimento |

Cada aplicação tem o próprio `README.md` com a arquitetura e as instruções para rodar.