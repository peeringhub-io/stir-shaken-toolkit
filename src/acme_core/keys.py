"""EC P-256 key management and ACME JWS signing helpers."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Literal

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

from acme_core import base64url
from acme_core.errors import AcmeClientError

KEY_MODE = 0o600
EmptyPayloadSigningMode = Literal["standard", "protected_only"]


class AcmeKeyManager:
    """Manage an ACME account key and related derived values."""

    def __init__(self, key_path: Path, kid: str) -> None:
        self.key_path = key_path
        self.kid = kid

    def load_or_create(self) -> EllipticCurvePrivateKey:
        """Load the account key, creating one if it is absent."""

        if self.key_path.exists():
            return self.load()
        self.key_path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        private_key = ec.generate_private_key(ec.SECP256R1())
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        temporary_path = self.key_path.with_name(f".{self.key_path.name}.tmp")
        temporary_path.write_bytes(pem)
        os.chmod(temporary_path, KEY_MODE)
        os.replace(temporary_path, self.key_path)
        return private_key

    def load(self) -> EllipticCurvePrivateKey:
        """Load an existing EC P-256 private key."""

        if not self.key_path.exists():
            raise AcmeClientError(f"ACME account key is missing: {self.key_path}")
        key = serialization.load_pem_private_key(
            self.key_path.read_bytes(), password=None
        )
        if not isinstance(key, EllipticCurvePrivateKey):
            raise AcmeClientError("ACME account key is not an elliptic curve key")
        if not isinstance(key.curve, ec.SECP256R1):
            raise AcmeClientError("ACME account key must use P-256")
        return key

    def jwk(
        self, private_key: EllipticCurvePrivateKey, include_kid: bool = False
    ) -> dict[str, str]:
        """Return a public JWK for the ACME account key."""

        public_numbers = private_key.public_key().public_numbers()
        jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": base64url.encode(public_numbers.x.to_bytes(32, "big")),
            "y": base64url.encode(public_numbers.y.to_bytes(32, "big")),
        }
        if include_kid:
            jwk["kid"] = self.kid
        return jwk

    def public_key_fingerprint(self, private_key: EllipticCurvePrivateKey) -> str:
        """Return the SHA256 public-key fingerprint used by STI-PA ATC binding."""

        der = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        digest = hashlib.sha256(der).hexdigest().upper()
        return f"SHA256 {':'.join(digest[index:index + 2] for index in range(0, len(digest), 2))}"

    def sign_jws(
        self,
        private_key: EllipticCurvePrivateKey,
        protected: dict[str, Any],
        payload: dict[str, Any] | None,
        empty_payload_signing_mode: EmptyPayloadSigningMode = "standard",
    ) -> dict[str, str]:
        """Sign an ACME Flattened JSON JWS."""

        protected_bytes = json.dumps(
            protected, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        protected_encoded = base64url.encode(protected_bytes)
        payload_encoded = ""
        if payload is not None:
            payload_bytes = json.dumps(
                payload, separators=(",", ":"), sort_keys=True
            ).encode("utf-8")
            payload_encoded = base64url.encode(payload_bytes)
        signing_input = self.signing_input(
            protected_encoded, payload_encoded, payload, empty_payload_signing_mode
        )
        signature_der = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r_value, s_value = utils.decode_dss_signature(signature_der)
        signature = r_value.to_bytes(32, "big") + s_value.to_bytes(32, "big")
        return {
            "protected": protected_encoded,
            "payload": payload_encoded,
            "signature": base64url.encode(signature),
        }

    def signing_input(
        self,
        protected_encoded: str,
        payload_encoded: str,
        payload: dict[str, Any] | None,
        empty_payload_signing_mode: EmptyPayloadSigningMode,
    ) -> bytes:
        """Return JWS signing input."""

        if payload is None and empty_payload_signing_mode == "protected_only":
            return protected_encoded.encode("ascii")
        return f"{protected_encoded}.{payload_encoded}".encode("ascii")
