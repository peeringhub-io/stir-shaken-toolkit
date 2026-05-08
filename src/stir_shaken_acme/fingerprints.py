"""STI-PA fingerprint helpers for certificates, CSRs, and keys."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

from .errors import ShakenValidationError


class FingerprintCalculator:
    """Calculate STI-PA formatted SHA256 fingerprints."""

    @staticmethod
    def from_certificate(path: Path) -> str:
        """Calculate a SHA256 fingerprint from a PEM certificate.

        :param path: PEM certificate path.
        :type path: Path
        :return: STI-PA formatted SHA256 fingerprint.
        :rtype: str
        :raises ShakenValidationError: If the certificate cannot be parsed.
        """

        try:
            certificate = x509.load_pem_x509_certificate(path.read_bytes())
        except ValueError as exc:
            raise ShakenValidationError(f"Failed to read certificate: {path}") from exc
        return FingerprintCalculator.format_digest(
            certificate.fingerprint(hashes.SHA256())
        )

    @staticmethod
    def from_csr(path: Path) -> str:
        """Calculate a SHA256 public-key fingerprint from a PEM CSR.

        :param path: PEM CSR path.
        :type path: Path
        :return: STI-PA formatted SHA256 fingerprint.
        :rtype: str
        :raises ShakenValidationError: If the CSR cannot be parsed.
        """

        try:
            csr = x509.load_pem_x509_csr(path.read_bytes())
        except ValueError as exc:
            raise ShakenValidationError(f"Failed to read CSR: {path}") from exc
        return FingerprintCalculator.from_public_key(csr.public_key())

    @staticmethod
    def from_private_key(path: Path) -> str:
        """Calculate a SHA256 public-key fingerprint from a PEM private key.

        :param path: PEM private key path.
        :type path: Path
        :return: STI-PA formatted SHA256 fingerprint.
        :rtype: str
        :raises ShakenValidationError: If the key cannot be parsed.
        """

        try:
            private_key = serialization.load_pem_private_key(
                path.read_bytes(), password=None
            )
        except (TypeError, ValueError) as exc:
            raise ShakenValidationError(f"Failed to read private key: {path}") from exc
        if not isinstance(private_key, EllipticCurvePrivateKey):
            raise ShakenValidationError(
                f"Private key is not an elliptic curve key: {path}"
            )
        return FingerprintCalculator.from_public_key(private_key.public_key())

    @staticmethod
    def from_public_key(public_key: Any) -> str:
        """Calculate a SHA256 fingerprint from a public key object.

        :param public_key: Cryptography public key object.
        :type public_key: Any
        :return: STI-PA formatted SHA256 fingerprint.
        :rtype: str
        """

        der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return FingerprintCalculator.format_digest(hashlib.sha256(der).digest())

    @staticmethod
    def format_digest(digest: bytes) -> str:
        """Format a binary digest as STI-PA SHA256 fingerprint text.

        :param digest: Binary digest.
        :type digest: bytes
        :return: STI-PA formatted SHA256 fingerprint.
        :rtype: str
        """

        hex_pairs = ":".join(f"{value:02X}" for value in digest)
        return f"SHA256 {hex_pairs}"
