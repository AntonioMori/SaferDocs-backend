"""Autenticador WebAuthn de software, para testar as passkeys sem navegador.

Gera as mesmas estruturas que um autenticador real manda pelo navegador:
clientDataJSON, authenticatorData (hash do rpId, flags, contador, dados da
credencial com a chave pública COSE) e a assinatura ECDSA P-256 da asserção.
"""

import base64
import hashlib
import json
import os
import struct
import uuid
from dataclasses import dataclass, field

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

FLAG_UP = 0x01  # usuário presente
FLAG_UV = 0x04  # usuário verificado (biometria/PIN)
FLAG_AT = 0x40  # há dados da credencial


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


@dataclass
class SoftAuthenticator:
    rp_id: str = "localhost"
    origin: str = "http://localhost:3039"
    aaguid: uuid.UUID = field(default_factory=uuid.uuid4)
    sign_count: int = 0
    counts_up: bool = True  # passkeys sincronizadas mandam sempre 0
    user_verified: bool = True
    key: ec.EllipticCurvePrivateKey = field(default_factory=lambda: ec.generate_private_key(ec.SECP256R1()))
    credential_id: bytes = field(default_factory=lambda: os.urandom(32))
    user_handle: bytes | None = None

    def _cose_key(self) -> bytes:
        numbers = self.key.public_key().public_numbers()
        return cbor2.dumps(
            {1: 2, 3: -7, -1: 1, -2: numbers.x.to_bytes(32, "big"), -3: numbers.y.to_bytes(32, "big")}
        )

    def _client_data(self, kind: str, challenge: str, origin: str | None) -> bytes:
        data = {"type": kind, "challenge": challenge, "origin": origin or self.origin, "crossOrigin": False}
        return json.dumps(data, separators=(",", ":")).encode()

    def _flags(self, extra: int = 0) -> int:
        return FLAG_UP | (FLAG_UV if self.user_verified else 0) | extra

    def create(self, options: dict, *, origin: str | None = None, rp_id: str | None = None) -> dict:
        """Resposta do navigator.credentials.create para as `options` do servidor."""
        self.user_handle = b64url_decode(options["user"]["id"])
        client_data = self._client_data("webauthn.create", options["challenge"], origin)
        auth_data = (
            hashlib.sha256((rp_id or self.rp_id).encode()).digest()
            + bytes([self._flags(FLAG_AT)])
            + struct.pack(">I", self.sign_count)
            + self.aaguid.bytes
            + struct.pack(">H", len(self.credential_id))
            + self.credential_id
            + self._cose_key()
        )
        attestation = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {
            "id": b64url(self.credential_id),
            "rawId": b64url(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url(client_data),
                "attestationObject": b64url(attestation),
                "transports": ["internal", "hybrid"],
            },
            "clientExtensionResults": {},
            "authenticatorAttachment": "platform",
        }

    def get(
        self,
        options: dict,
        *,
        origin: str | None = None,
        rp_id: str | None = None,
        sign_count: int | None = None,
    ) -> dict:
        """Resposta do navigator.credentials.get para as `options` do servidor."""
        if sign_count is not None:
            self.sign_count = sign_count
        elif self.counts_up:
            self.sign_count += 1
        client_data = self._client_data("webauthn.get", options["challenge"], origin)
        auth_data = (
            hashlib.sha256((rp_id or self.rp_id).encode()).digest()
            + bytes([self._flags()])
            + struct.pack(">I", self.sign_count)
        )
        signature = self.key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        return {
            "id": b64url(self.credential_id),
            "rawId": b64url(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64url(client_data),
                "authenticatorData": b64url(auth_data),
                "signature": b64url(signature),
                "userHandle": b64url(self.user_handle or b""),
            },
            "clientExtensionResults": {},
            "authenticatorAttachment": "platform",
        }
