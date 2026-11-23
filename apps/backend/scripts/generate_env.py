"""Gera um `.env` de desenvolvimento a partir do `.env.example`.

Preenche os segredos com valores aleatórios novos: senha do Postgres, par
ES256 do JWT, MASTER_KEY e HASH_PEPPER. Não sobrescreve um `.env` existente
sem `--force`.

Uso (dentro de apps/backend):
    uv run python scripts/generate_env.py [--force] [--local]

`--local` aponta o DATABASE_URL para localhost (API rodando fora do Docker).
"""

import argparse
import base64
import re
import secrets
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / ".env.example"
TARGET = ROOT / ".env"


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def es256_pair() -> tuple[str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    private = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return b64(private), b64(public)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--force", action="store_true", help="sobrescreve o .env existente")
    parser.add_argument("--local", action="store_true", help="DATABASE_URL com host localhost")
    args = parser.parse_args()

    if TARGET.exists() and not args.force:
        raise SystemExit(".env já existe. Use --force para sobrescrever.")

    db_password = secrets.token_urlsafe(24)
    private, public = es256_pair()
    host = "localhost" if args.local else "db"
    values = {
        "POSTGRES_PASSWORD": db_password,
        "DATABASE_URL": f"postgresql+psycopg://saferdocs:{db_password}@{host}:5432/saferdocs",
        "JWT_PRIVATE_KEY_PEM_B64": private,
        "JWT_PUBLIC_KEY_PEM_B64": public,
        "MASTER_KEY": b64(secrets.token_bytes(32)),
        "HASH_PEPPER": b64(secrets.token_bytes(32)),
    }

    text = EXAMPLE.read_text(encoding="utf-8")
    for name, value in values.items():
        text, count = re.subn(rf"^{name}=.*$", f"{name}={value}", text, flags=re.MULTILINE)
        if count != 1:
            raise SystemExit(f"Variável {name} não encontrada no .env.example")

    TARGET.write_text(text, encoding="utf-8")
    print(f".env gerado em {TARGET}")


if __name__ == "__main__":
    main()
