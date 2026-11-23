"""Gera um access token de desenvolvimento para testar rotas protegidas.

Cria o usuário se ele não existir (sem senha utilizável), abre uma sessão
para ele e imprime um JWT válido por ACCESS_TOKEN_TTL_SECONDS. Recusa rodar
com APP_ENV=production.

O token só é aceito com o mesmo User-Agent informado aqui (REQ-27). O curl
envia "curl/<versão>"; por isso o padrão é passar o UA explicitamente:

Uso (dentro de apps/backend, com o banco no ar):
    TOKEN=$(uv run python scripts/dev_token.py --user-agent dev)
    curl -A dev -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/api/v1/...
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import func, select  # noqa: E402

from app.core.config import get_settings  # noqa: E402
from app.crypto.jwt import encode_access_token  # noqa: E402
from app.crypto.keyed_hash import keyed_hash  # noqa: E402
from app.db.models import User, UserSession  # noqa: E402
from app.db.session import get_sessionmaker  # noqa: E402

UNUSABLE_PASSWORD = "!dev-token-sem-senha"  # não é um hash Argon2: nunca autentica por senha


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--email", default="dev@saferdocs.local")
    parser.add_argument("--name", default="Usuário de desenvolvimento")
    parser.add_argument("--user-agent", default="dev", help="User-Agent que vai usar nas requisições")
    parser.add_argument("--ip", default="127.0.0.1", help="IP de origem esperado")
    args = parser.parse_args()

    if get_settings().is_production:
        raise SystemExit("dev_token.py não pode ser usado em produção.")

    with get_sessionmaker()() as db:
        user = db.scalar(select(User).where(func.lower(User.email) == args.email.lower()))
        if user is None:
            user = User(name=args.name, email=args.email.lower(), password_hash=UNUSABLE_PASSWORD)
            db.add(user)
            db.flush()
        session = UserSession(
            user_id=user.id,
            ip=args.ip,
            user_agent=args.user_agent,
            ip_hmac=keyed_hash(args.ip),
            ua_hmac=keyed_hash(args.user_agent),
        )
        db.add(session)
        db.commit()
        token, _ = encode_access_token(user.id, {"session_id": str(session.id), "ua_hash": session.ua_hmac})
    print(token)


if __name__ == "__main__":
    main()
