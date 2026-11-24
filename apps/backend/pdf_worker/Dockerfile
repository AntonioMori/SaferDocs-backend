# Imagem do pdf-worker (REQ-62). Build a partir de apps/backend:
#   docker build -f pdf_worker/Dockerfile --target runtime .
# O isolamento em tempo de execução (sem rede, só leitura, sem capabilities,
# limites de memória/CPU/processos) está no docker-compose.yml.

# --- runtime: o que roda em produção
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY pdf_worker/requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt && rm /tmp/requirements.txt

# Usuário próprio, sem shell de login. O diretório do socket pertence a ele e ao
# grupo 10001, que a API também recebe (group_add no compose).
RUN groupadd --gid 10001 pdfworker \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin pdfworker \
    && mkdir -p /run/pdf \
    && chown 10001:10001 /run/pdf \
    && chmod 0750 /run/pdf

COPY pdf_worker /app/pdf_worker

USER 10001:10001
CMD ["python", "-E", "-s", "-m", "pdf_worker.server"]

# --- test: a mesma base, mais o pytest, para os testes que só rodam no Linux
#   docker compose --profile test run --rm worker-tests
FROM runtime AS test
USER root
RUN pip install "pytest>=9.2" "cryptography>=50.0.2" "sqlalchemy>=2.1.9"
USER 10001:10001
WORKDIR /src
CMD ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/test_pdf_worker_server.py"]
