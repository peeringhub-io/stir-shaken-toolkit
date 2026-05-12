"""SHAKEN certificate key, CSR, and validation helpers."""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.x509.oid import ExtensionOID, NameOID, ObjectIdentifier

from .errors import ShakenValidationError

TNAUTHLIST_OID = ObjectIdentifier("1.3.6.1.5.5.7.1.26")
SHAKEN_POLICY_OID_ARC = "2.16.840.1.114569.1.1"
LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class ShakenSubject:
    """X.509 subject values for a SHAKEN CSR."""

    country: str
    state: str
    locality: str
    organization: str
    common_name: str
    organizational_unit: str = ""

    def to_x509_name(self) -> x509.Name:
        """Return the subject as an X.509 name."""

        attributes = [
            x509.NameAttribute(NameOID.COUNTRY_NAME, self.country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, self.state),
            x509.NameAttribute(NameOID.LOCALITY_NAME, self.locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.organization),
        ]
        if self.organizational_unit:
            attributes.append(
                x509.NameAttribute(
                    NameOID.ORGANIZATIONAL_UNIT_NAME, self.organizational_unit
                )
            )
        attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, self.common_name))
        return x509.Name(attributes)


@dataclass(frozen=True)
class ShakenCertificatePolicy:
    """Policy for building and validating a SHAKEN certificate."""

    subject: ShakenSubject
    tn_auth_list_der: bytes
    expected_crl_url: str
    minimum_certificate_lifetime_days: int
    include_crl_distribution_points: bool = True
    require_shaken_policy: bool = True
    accepted_shaken_policy_oids: frozenset[ObjectIdentifier] | None = None


@dataclass(frozen=True)
class CertificateDetails:
    """Extracted SHAKEN certificate details."""

    serial_number: str
    not_before: str
    not_after: str
    issuer: str
    subject: str
    fingerprint_sha256: str

    def as_dict(self) -> dict[str, str]:
        """Return details as a JSON-ready mapping."""

        return {
            "serial_number": self.serial_number,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "issuer": self.issuer,
            "subject": self.subject,
            "fingerprint_sha256": self.fingerprint_sha256,
        }


class ShakenCertificateManager:
    """Manage SHAKEN certificate keys, CSRs, and validation."""

    def __init__(self, policy: ShakenCertificatePolicy | None = None) -> None:
        self.policy: ShakenCertificatePolicy | None = policy

    def generate_certificate_key(self, path: Path) -> EllipticCurvePrivateKey:
        """Generate a per-certificate EC P-256 key."""

        private_key = ec.generate_private_key(ec.SECP256R1())
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        path.write_bytes(pem)
        os.chmod(path, 0o600)
        return private_key

    def load_certificate_key(self, path: Path) -> EllipticCurvePrivateKey:
        """Load a SHAKEN certificate private key."""

        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, EllipticCurvePrivateKey) or not isinstance(
            key.curve, ec.SECP256R1
        ):
            raise ShakenValidationError(f"SHAKEN private key must be EC P-256: {path}")
        return key

    def build_subject(self) -> x509.Name:
        """Build the configured certificate subject."""

        return self.require_policy().subject.to_x509_name()

    def build_csr(
        self, private_key: EllipticCurvePrivateKey
    ) -> x509.CertificateSigningRequest:
        """Build a SHAKEN-compatible CSR."""

        policy = self.require_policy()
        builder = x509.CertificateSigningRequestBuilder().subject_name(
            policy.subject.to_x509_name()
        )
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        builder = builder.add_extension(
            x509.UnrecognizedExtension(TNAUTHLIST_OID, policy.tn_auth_list_der),
            critical=False,
        )
        if policy.include_crl_distribution_points:
            builder = builder.add_extension(
                x509.CRLDistributionPoints(
                    [
                        x509.DistributionPoint(
                            full_name=[
                                x509.UniformResourceIdentifier(policy.expected_crl_url)
                            ],
                            relative_name=None,
                            reasons=None,
                            crl_issuer=None,
                        ),
                    ]
                ),
                critical=False,
            )
        return builder.sign(private_key, hashes.SHA256())

    def csr_pem(self, csr: x509.CertificateSigningRequest) -> bytes:
        """Return CSR PEM bytes."""

        return csr.public_bytes(serialization.Encoding.PEM)

    def csr_der(self, csr: x509.CertificateSigningRequest) -> bytes:
        """Return CSR DER bytes."""

        return csr.public_bytes(serialization.Encoding.DER)

    def extract_leaf_pem(self, chain_pem: str) -> str:
        """Extract the first PEM certificate from a chain."""

        start = chain_pem.find("-----BEGIN CERTIFICATE-----")
        end = chain_pem.find("-----END CERTIFICATE-----", start)
        if start < 0 or end < 0:
            raise ShakenValidationError(
                "Issued certificate chain does not contain a PEM certificate"
            )
        end += len("-----END CERTIFICATE-----")
        return f"{chain_pem[start:end]}\n"

    def parse_certificate(self, pem: bytes | str) -> x509.Certificate:
        """Parse a PEM certificate."""

        data = pem.encode("utf-8") if isinstance(pem, str) else pem
        return x509.load_pem_x509_certificate(data)

    def parse_csr(self, pem: bytes | str) -> x509.CertificateSigningRequest:
        """Parse a PEM certificate signing request."""

        data = pem.encode("utf-8") if isinstance(pem, str) else pem
        return x509.load_pem_x509_csr(data)

    def validate_issued_certificate(
        self,
        certificate: x509.Certificate,
        private_key: EllipticCurvePrivateKey,
    ) -> CertificateDetails:
        """Validate an issued SHAKEN certificate."""

        try:
            return self.validate_issued_certificate_policy(certificate, private_key)
        except x509.ExtensionNotFound as exc:
            validation_error = ShakenValidationError(
                f"Issued certificate missing extension OID {exc.oid.dotted_string}"
            )
            LOGGER.error(
                "Issued certificate validation failed: error=%s diagnostics=%s",
                validation_error,
                json.dumps(
                    self.certificate_diagnostics(certificate),
                    sort_keys=True,
                ),
            )
            raise validation_error from exc
        except ShakenValidationError as exc:
            LOGGER.error(
                "Issued certificate validation failed: error=%s diagnostics=%s",
                exc,
                json.dumps(
                    self.certificate_diagnostics(certificate),
                    sort_keys=True,
                ),
            )
            raise

    def validate_issued_certificate_policy(
        self,
        certificate: x509.Certificate,
        private_key: EllipticCurvePrivateKey,
    ) -> CertificateDetails:
        """Validate an issued SHAKEN certificate policy."""

        policy = self.require_policy()
        self.require_certificate_private_key_match(certificate, private_key)
        public_key = certificate.public_key()
        if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
            public_key.curve, ec.SECP256R1
        ):
            raise ShakenValidationError(
                "Issued certificate public key must be EC P-256"
            )
        now = datetime.now(UTC)
        not_before = certificate.not_valid_before_utc
        not_after = certificate.not_valid_after_utc
        if (
            now + timedelta(minutes=5) < not_before
            or now - timedelta(minutes=5) > not_after
        ):
            raise ShakenValidationError("Issued certificate is not currently valid")
        if not_after <= now + timedelta(days=policy.minimum_certificate_lifetime_days):
            raise ShakenValidationError(
                "Issued certificate expires before minimum lifetime threshold"
            )
        expected_subject = policy.subject.to_x509_name()
        if certificate.subject != expected_subject:
            raise ShakenValidationError(
                f"Issued certificate subject mismatch: {certificate.subject.rfc4514_string()}"
            )
        basic_constraints = certificate.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
        if (
            not isinstance(basic_constraints, x509.BasicConstraints)
            or basic_constraints.ca
        ):
            raise ShakenValidationError(
                "Issued certificate Basic Constraints must be CA:FALSE"
            )
        tn_auth_extension = certificate.extensions.get_extension_for_oid(
            TNAUTHLIST_OID
        ).value
        if (
            not isinstance(tn_auth_extension, x509.UnrecognizedExtension)
            or tn_auth_extension.value != policy.tn_auth_list_der
        ):
            raise ShakenValidationError(
                "Issued certificate TNAuthList extension mismatch"
            )
        crl_distribution_points = certificate.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS
        ).value
        if not isinstance(crl_distribution_points, x509.CRLDistributionPoints):
            raise ShakenValidationError(
                "Issued certificate CRL Distribution Points extension is " + "invalid"
            )
        self.require_expected_crl(crl_distribution_points, policy.expected_crl_url)
        if policy.require_shaken_policy:
            policies = certificate.extensions.get_extension_for_oid(
                ExtensionOID.CERTIFICATE_POLICIES
            ).value
            if not isinstance(policies, x509.CertificatePolicies):
                raise ShakenValidationError(
                    "Issued certificate Certificate Policies extension is " + "invalid"
                )
            certificate_policy_oids = {
                policy_item.policy_identifier for policy_item in policies
            }
            self.require_shaken_policy_oid(certificate_policy_oids, policy)
        fingerprint = certificate.fingerprint(hashes.SHA256()).hex().upper()
        return CertificateDetails(
            serial_number=str(certificate.serial_number),
            not_before=not_before.isoformat().replace("+00:00", "Z"),
            not_after=not_after.isoformat().replace("+00:00", "Z"),
            issuer=certificate.issuer.rfc4514_string(),
            subject=certificate.subject.rfc4514_string(),
            fingerprint_sha256=":".join(
                fingerprint[index : index + 2]
                for index in range(0, len(fingerprint), 2)
            ),
        )

    def require_certificate_private_key_match(
        self, certificate: x509.Certificate, private_key: EllipticCurvePrivateKey
    ) -> None:
        """Validate that a certificate public key matches a private key."""

        if not self._public_keys_match(certificate.public_key(), private_key):
            raise ShakenValidationError(
                "Certificate public key does not match private key"
            )

    def require_csr_private_key_match(
        self,
        csr: x509.CertificateSigningRequest,
        private_key: EllipticCurvePrivateKey,
    ) -> None:
        """Validate that a CSR public key matches a private key."""

        if not csr.is_signature_valid:
            raise ShakenValidationError("CSR signature is invalid")
        if not self._public_keys_match(csr.public_key(), private_key):
            raise ShakenValidationError("CSR public key does not match private key")

    def _public_keys_match(
        self,
        public_key: Any,
        private_key: EllipticCurvePrivateKey,
    ) -> bool:
        """Return whether a public key matches a private key public component."""

        public_der = public_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        private_der = private_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return (
            hashlib.sha256(public_der).digest() == hashlib.sha256(private_der).digest()
        )

    def require_expected_crl(
        self, crl_distribution_points: x509.CRLDistributionPoints, expected: str
    ) -> None:
        """Validate the certificate CRL distribution point URL."""

        for point in crl_distribution_points:
            for name in point.full_name or []:
                if (
                    isinstance(name, x509.UniformResourceIdentifier)
                    and name.value == expected
                ):
                    return
        raise ShakenValidationError(
            "Issued certificate missing expected STI-PA CRL URL"
        )

    def certificate_diagnostics(
        self, certificate: x509.Certificate
    ) -> dict[str, object]:
        """Return JSON-safe certificate diagnostics for validation failures.

        :param certificate: Certificate being validated.
        :type certificate: x509.Certificate
        :return: Certificate diagnostics.
        :rtype: dict[str, object]
        """

        return {
            "extension_oids": self.extension_oids(certificate),
            "issuer": certificate.issuer.rfc4514_string(),
            "policy_oids": self.policy_oids(certificate),
            "serial_number": str(certificate.serial_number),
            "subject": certificate.subject.rfc4514_string(),
        }

    def extension_oids(self, certificate: x509.Certificate) -> list[str]:
        """Return certificate extension OIDs.

        :param certificate: Certificate to inspect.
        :type certificate: x509.Certificate
        :return: Extension OID strings.
        :rtype: list[str]
        """

        return [extension.oid.dotted_string for extension in certificate.extensions]

    def policy_oids(self, certificate: x509.Certificate) -> list[str]:
        """Return certificate policy OIDs if present.

        :param certificate: Certificate to inspect.
        :type certificate: x509.Certificate
        :return: Certificate policy OID strings.
        :rtype: list[str]
        """

        try:
            policies = certificate.extensions.get_extension_for_oid(
                ExtensionOID.CERTIFICATE_POLICIES
            ).value
        except x509.ExtensionNotFound:
            return []
        if not isinstance(policies, x509.CertificatePolicies):
            return []
        return [policy_item.policy_identifier.dotted_string for policy_item in policies]

    def require_shaken_policy_oid(
        self,
        certificate_policy_oids: set[ObjectIdentifier],
        policy: ShakenCertificatePolicy,
    ) -> None:
        """Validate certificate policy OIDs against configured SHAKEN policy.

        :param certificate_policy_oids: Certificate policy OIDs from the certificate.
        :type certificate_policy_oids: set[ObjectIdentifier]
        :param policy: Validation policy.
        :type policy: ShakenCertificatePolicy
        :return: None.
        :rtype: None
        """

        if policy.accepted_shaken_policy_oids is not None:
            if certificate_policy_oids.isdisjoint(policy.accepted_shaken_policy_oids):
                raise ShakenValidationError(
                    "Issued certificate missing accepted SHAKEN policy OID"
                )
            return
        for policy_oid in certificate_policy_oids:
            if self.is_shaken_policy_oid(policy_oid):
                return
        raise ShakenValidationError(
            "Issued certificate missing STI-PA SHAKEN policy OID"
        )

    def is_shaken_policy_oid(self, policy_oid: ObjectIdentifier) -> bool:
        """Return whether an OID is under the STI-PA SHAKEN policy arc.

        :param policy_oid: Certificate policy OID.
        :type policy_oid: ObjectIdentifier
        :return: Whether the OID is under the SHAKEN policy arc.
        :rtype: bool
        """

        return policy_oid.dotted_string.startswith(f"{SHAKEN_POLICY_OID_ARC}.")

    def require_policy(self) -> ShakenCertificatePolicy:
        """Return the configured certificate policy."""

        if self.policy is None:
            raise ShakenValidationError("SHAKEN certificate policy is not configured")
        return self.policy
