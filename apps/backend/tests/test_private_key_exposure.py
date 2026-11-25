"""Chave privada nunca exposta (REQ-59): nem em resposta, nem em log, nem em erro, nem na auditoria.

Percorre um fluxo completo (cadastro, login, assinatura, histórico, /auth/me,
erros) e procura a chave privada do usuário em todas as formas em que ela
poderia vazar: DER, PEM, hex, base64, o escalar e o texto cifrado.
"""

import base64
import logging
import pickle
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.crypto.aead import AeadContext, decrypt
from app.db.models import AuditLog, User
from app.db.session import get_sessionmaker
from app.main import app
from app.services.user_keys import Redacted
from tests.conftest import make_pdf, session_token

SENHA = "Senha-Forte#2026"


def _formas_da_chave(user: User) -> list[bytes]:
    der = decrypt(AeadContext.SIGNING_KEY, user.signing_private_key_enc, associated_data=user.id.bytes)
    chave = serialization.load_der_private_key(der, password=None)
    pem = chave.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    escalar = chave.private_numbers().private_value.to_bytes(32, "big")
    formas = [der, pem, escalar, user.signing_private_key_enc]
    for valor in (der, escalar, user.signing_private_key_enc):
        formas += [
            valor.hex().encode(),
            base64.b64encode(valor),
            base64.urlsafe_b64encode(valor).rstrip(b"="),
        ]
    return formas


def test_fluxo_completo_nao_expoe_a_chave_em_respostas_logs_ou_auditoria(
    migrated_db, fake_pdf_worker, caplog, monkeypatch
):
    client = TestClient(app)
    email = f"chave-{uuid.uuid4().hex[:10]}@teste.dev"
    with caplog.at_level(logging.DEBUG):
        respostas = [
            client.post("/api/v1/auth/register", json={"name": "Ana", "email": email, "password": SENHA})
        ]
        respostas.append(client.post("/api/v1/auth/login", json={"email": email, "password": SENHA}))
        with get_sessionmaker()() as db:
            user = db.scalar(select(User).where(User.email == email))
            db.expunge(user)
        headers = {"Authorization": f"Bearer {session_token(user.id)}"}
        arquivo = {"file": ("d.pdf", make_pdf(), "application/pdf")}
        respostas.append(
            client.post(
                "/api/v1/documents/sign",
                files=arquivo,
                data={"page": "1", "x": "1", "y": "1"},
                headers=headers,
            )
        )
        respostas.append(client.get("/api/v1/documents/signatures", headers=headers))
        respostas.append(client.get("/api/v1/auth/me", headers=headers))
        # Erros: posição inválida, PDF quebrado e a chave cifrada corrompida (erro interno).
        respostas.append(
            client.post(
                "/api/v1/documents/sign",
                files=arquivo,
                data={"page": "9", "x": "1", "y": "1"},
                headers=headers,
            )
        )
        with get_sessionmaker()() as db:
            corrompido = db.get(User, user.id)
            original_enc = corrompido.signing_private_key_enc
            corrompido.signing_private_key_enc = original_enc[:-1] + bytes([original_enc[-1] ^ 1])
            db.commit()
        respostas.append(
            client.post(
                "/api/v1/documents/sign",
                files=arquivo,
                data={"page": "1", "x": "1", "y": "1"},
                headers=headers,
            )
        )
        with get_sessionmaker()() as db:
            db.get(User, user.id).signing_private_key_enc = original_enc
            db.commit()

    assert [r.status_code for r in respostas] == [201, 200, 200, 200, 200, 400, 500]
    saidas = [r.content for r in respostas] + [str(dict(r.headers)).encode() for r in respostas]
    saidas.append(caplog.text.encode())
    with get_sessionmaker()() as db:
        saidas += [
            repr(a.details).encode() for a in db.scalars(select(AuditLog).where(AuditLog.user_id == user.id))
        ]
    tudo = b"\n".join(saidas)
    for forma in _formas_da_chave(user):
        assert forma not in tudo
    assert b"PRIVATE KEY" not in tudo


def test_schemas_de_resposta_nao_tem_campos_de_chave():
    from app.schemas import auth, documents, security, sessions, twofa

    for modulo in (auth, documents, security, sessions, twofa):
        for nome in dir(modulo):
            schema = getattr(modulo, nome)
            campos = getattr(schema, "model_fields", None)
            if isinstance(campos, dict):
                assert not [c for c in campos if "private" in c or "signing_" in c or c.endswith("_enc")], (
                    nome
                )


def test_redacted_nao_mostra_o_valor():
    segredo = Redacted(b"\x30\x81\x87chave-privada")
    for texto in (repr(segredo), str(segredo), f"{segredo}", f"{segredo!r}", "%s" % (segredo,)):  # noqa: UP031 - o formato % é usado em logs
        assert "chave" not in texto and texto == "<oculto>"
    logging.getLogger("teste").error("valor: %s", segredo)
    with pytest.raises(TypeError):
        pickle.dumps(segredo)
    assert segredo.reveal() == b"\x30\x81\x87chave-privada"
