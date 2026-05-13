"""X.509 certificate and CSR inspection helpers."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    ExtensionOID,
    ObjectIdentifier,
)

from .certificates import TNAUTHLIST_OID
from .fingerprints import FingerprintCalculator

PEM_CERTIFICATE_BEGIN = b"-----BEGIN CERTIFICATE-----"
PEM_CSR_BEGIN = b"-----BEGIN CERTIFICATE REQUEST-----"
PROJECT_OID_NAMES = {
    TNAUTHLIST_OID.dotted_string: "TNAuthList",
}


@dataclass(frozen=True)
class CertificateInspection:
    """JSON-safe inspection result for one certificate."""

    data: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        """Return inspection data as a JSON-ready mapping.

        :return: Inspection data.
        :rtype: dict[str, Any]
        """

        return self.data


@dataclass(frozen=True)
class CsrInspection:
    """JSON-safe inspection result for one CSR."""

    data: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        """Return inspection data as a JSON-ready mapping.

        :return: Inspection data.
        :rtype: dict[str, Any]
        """

        return self.data


class CertificateInspector:
    """Inspect X.509 certificates, certificate bundles, and CSRs."""

    def inspect_certificate_bytes(self, data: bytes) -> CertificateInspection:
        """Inspect one PEM certificate.

        :param data: PEM certificate bytes.
        :type data: bytes
        :return: Certificate inspection.
        :rtype: CertificateInspection
        """

        certificate = x509.load_pem_x509_certificate(data)
        return self.inspect_certificate(certificate)

    def inspect_pem_bundle_bytes(self, data: bytes) -> list[CertificateInspection]:
        """Inspect all PEM certificates in a bundle.

        :param data: PEM certificate bundle bytes.
        :type data: bytes
        :return: Certificate inspections in bundle order.
        :rtype: list[CertificateInspection]
        """

        certificates = x509.load_pem_x509_certificates(data)
        return [self.inspect_certificate(certificate) for certificate in certificates]

    def inspect_csr_bytes(self, data: bytes) -> CsrInspection:
        """Inspect one PEM certificate signing request.

        :param data: PEM CSR bytes.
        :type data: bytes
        :return: CSR inspection.
        :rtype: CsrInspection
        """

        csr = x509.load_pem_x509_csr(data)
        return self.inspect_csr(csr)

    def inspect_certificate(
        self, certificate: x509.Certificate
    ) -> CertificateInspection:
        """Inspect a parsed certificate.

        :param certificate: Parsed certificate.
        :type certificate: x509.Certificate
        :return: Certificate inspection.
        :rtype: CertificateInspection
        """

        fingerprint = certificate.fingerprint(hashes.SHA256())
        inspection = {
            "type": "certificate",
            "subject": self.name_dict(certificate.subject),
            "subject_rfc4514": certificate.subject.rfc4514_string(),
            "issuer": self.name_dict(certificate.issuer),
            "issuer_rfc4514": certificate.issuer.rfc4514_string(),
            "serial_number": str(certificate.serial_number),
            "serial_number_hex": f"{certificate.serial_number:X}",
            "version": certificate.version.name,
            "not_before": self.iso_utc(certificate.not_valid_before_utc),
            "not_after": self.iso_utc(certificate.not_valid_after_utc),
            "fingerprint_sha256": self.format_colon_hex(fingerprint),
            "public_key_fingerprint_sha256": (
                FingerprintCalculator.from_public_key(certificate.public_key())
            ),
            "signature_algorithm": self.signature_algorithm_name(certificate),
            "public_key": self.public_key_dict(certificate.public_key()),
            "extensions": self.extensions_list(certificate.extensions),
        }
        inspection.update(self.derived_certificate_fields(inspection))
        return CertificateInspection(inspection)

    def inspect_csr(self, csr: x509.CertificateSigningRequest) -> CsrInspection:
        """Inspect a parsed CSR.

        :param csr: Parsed CSR.
        :type csr: x509.CertificateSigningRequest
        :return: CSR inspection.
        :rtype: CsrInspection
        """

        inspection = {
            "type": "csr",
            "subject": self.name_dict(csr.subject),
            "subject_rfc4514": csr.subject.rfc4514_string(),
            "signature_valid": csr.is_signature_valid,
            "signature_algorithm": self.signature_algorithm_name(csr),
            "public_key_fingerprint_sha256": (
                FingerprintCalculator.from_public_key(csr.public_key())
            ),
            "public_key": self.public_key_dict(csr.public_key()),
            "extensions": self.extensions_list(csr.extensions),
        }
        inspection["tn_auth_list_spc"] = self.tn_auth_list_spc(inspection)
        return CsrInspection(inspection)

    def derived_certificate_fields(self, inspection: dict[str, Any]) -> dict[str, Any]:
        """Return derived certificate fields from parsed extensions.

        :param inspection: Certificate inspection data.
        :type inspection: dict[str, Any]
        :return: Derived certificate fields.
        :rtype: dict[str, Any]
        """

        return {
            "subject_key_identifier": self.extension_digest(
                inspection, ExtensionOID.SUBJECT_KEY_IDENTIFIER.dotted_string, "digest"
            ),
            "authority_key_identifier": self.extension_digest(
                inspection,
                ExtensionOID.AUTHORITY_KEY_IDENTIFIER.dotted_string,
                "key_identifier",
            ),
            "certificate_policy_oids": self.certificate_policy_oids(inspection),
            "crl_distribution_points": self.crl_distribution_points(inspection),
            "tn_auth_list_spc": self.tn_auth_list_spc(inspection),
        }

    def extension_digest(
        self, inspection: dict[str, Any], oid: str, field_name: str
    ) -> str | None:
        """Return a digest-style value from an inspection extension.

        :param inspection: Certificate or CSR inspection data.
        :type inspection: dict[str, Any]
        :param oid: Extension OID.
        :type oid: str
        :param field_name: Parsed extension value field name.
        :type field_name: str
        :return: Digest value.
        :rtype: str | None
        """

        value = self.inspection_extension_value(inspection, oid)
        if not isinstance(value, dict):
            return None
        digest = value.get(field_name)
        return str(digest) if digest is not None else None

    def certificate_policy_oids(self, inspection: dict[str, Any]) -> list[str]:
        """Return certificate policy OIDs from inspection data.

        :param inspection: Certificate inspection data.
        :type inspection: dict[str, Any]
        :return: Certificate policy OIDs.
        :rtype: list[str]
        """

        value = self.inspection_extension_value(
            inspection, ExtensionOID.CERTIFICATE_POLICIES.dotted_string
        )
        if not isinstance(value, list):
            return []
        policy_oids = []
        for policy in value:
            if not isinstance(policy, dict):
                continue
            identifier = policy.get("policy_identifier")
            if isinstance(identifier, dict) and identifier.get("oid") is not None:
                policy_oids.append(str(identifier["oid"]))
        return policy_oids

    def crl_distribution_points(self, inspection: dict[str, Any]) -> list[str]:
        """Return CRL distribution point URI values.

        :param inspection: Certificate inspection data.
        :type inspection: dict[str, Any]
        :return: CRL distribution point URIs.
        :rtype: list[str]
        """

        value = self.inspection_extension_value(
            inspection, ExtensionOID.CRL_DISTRIBUTION_POINTS.dotted_string
        )
        if not isinstance(value, list):
            return []
        urls = []
        for point in value:
            if not isinstance(point, dict):
                continue
            for name in point.get("full_name", []):
                if isinstance(name, dict) and name.get("value") is not None:
                    urls.append(str(name["value"]))
        return urls

    def tn_auth_list_spc(self, inspection: dict[str, Any]) -> str | None:
        """Return the decoded TNAuthList SPC from inspection data.

        :param inspection: Certificate or CSR inspection data.
        :type inspection: dict[str, Any]
        :return: SPC value.
        :rtype: str | None
        """

        value = self.inspection_extension_value(
            inspection, TNAUTHLIST_OID.dotted_string
        )
        if not isinstance(value, dict):
            return None
        tn_auth_list = value.get("tn_auth_list")
        if not isinstance(tn_auth_list, dict):
            return None
        spc = tn_auth_list.get("spc")
        return str(spc) if spc is not None else None

    def inspection_extension_value(self, inspection: dict[str, Any], oid: str) -> Any:
        """Return a parsed inspection extension value.

        :param inspection: Certificate or CSR inspection data.
        :type inspection: dict[str, Any]
        :param oid: Extension OID.
        :type oid: str
        :return: Parsed extension value.
        :rtype: Any
        """

        extensions = inspection.get("extensions")
        if not isinstance(extensions, list):
            return None
        for extension in extensions:
            if isinstance(extension, dict) and extension.get("oid") == oid:
                return extension.get("value")
        return None

    def extensions_list(self, extensions: x509.Extensions) -> list[dict[str, Any]]:
        """Return JSON-safe extension details.

        :param extensions: X.509 extensions.
        :type extensions: x509.Extensions
        :return: Extension details.
        :rtype: list[dict[str, Any]]
        """

        return [self.extension_dict(extension) for extension in extensions]

    def extension_dict(self, extension: x509.Extension[Any]) -> dict[str, Any]:
        """Return JSON-safe details for one extension.

        :param extension: X.509 extension.
        :type extension: x509.Extension[Any]
        :return: Extension details.
        :rtype: dict[str, Any]
        """

        value = extension.value
        return {
            "oid": extension.oid.dotted_string,
            "name": self.oid_name(extension.oid),
            "critical": extension.critical,
            "value": self.extension_value(value),
            "raw_value_base64": self.extension_raw_base64(value),
        }

    def extension_value(self, value: Any) -> Any:
        """Return a JSON-safe parsed extension value.

        :param value: Extension value.
        :type value: Any
        :return: Parsed extension value.
        :rtype: Any
        """

        if isinstance(value, x509.BasicConstraints):
            return {"ca": value.ca, "path_length": value.path_length}
        if isinstance(value, x509.KeyUsage):
            return self.key_usage_dict(value)
        if isinstance(value, x509.ExtendedKeyUsage):
            return [self.oid_dict(oid) for oid in value]
        if isinstance(value, x509.SubjectKeyIdentifier):
            return {"digest": self.format_colon_hex(value.digest)}
        if isinstance(value, x509.AuthorityKeyIdentifier):
            return self.authority_key_identifier_dict(value)
        if isinstance(value, x509.CertificatePolicies):
            return [self.certificate_policy_dict(policy) for policy in value]
        if isinstance(value, x509.CRLDistributionPoints):
            return [self.distribution_point_dict(point) for point in value]
        if isinstance(value, x509.SubjectAlternativeName):
            return [self.general_name_dict(name) for name in value]
        if isinstance(value, x509.IssuerAlternativeName):
            return [self.general_name_dict(name) for name in value]
        if isinstance(value, x509.AuthorityInformationAccess):
            return [self.access_description_dict(description) for description in value]
        if isinstance(value, x509.UnrecognizedExtension):
            return self.unrecognized_extension_dict(value)
        return str(value)

    def unrecognized_extension_dict(
        self, value: x509.UnrecognizedExtension
    ) -> dict[str, Any]:
        """Return details for an unrecognized extension.

        :param value: Unrecognized extension value.
        :type value: x509.UnrecognizedExtension
        :return: Extension details.
        :rtype: dict[str, Any]
        """

        details: dict[str, Any] = {
            "oid": value.oid.dotted_string,
            "value_base64": base64.b64encode(value.value).decode("ascii"),
        }
        if value.oid == TNAUTHLIST_OID:
            details["tn_auth_list"] = self.tn_auth_list_dict(value.value)
        return details

    def tn_auth_list_dict(self, der: bytes) -> dict[str, Any]:
        """Decode the project-supported SPC-only TNAuthList shape.

        :param der: TNAuthList DER bytes.
        :type der: bytes
        :return: TNAuthList details.
        :rtype: dict[str, Any]
        """

        details: dict[str, Any] = {
            "der_base64": base64.b64encode(der).decode("ascii"),
            "decoded": False,
        }
        if len(der) < 6:
            return details
        if der[0] != 0x30 or der[2] != 0xA0 or der[4] != 0x16:
            return details
        if der[1] != len(der) - 2 or der[3] != len(der) - 4:
            return details
        spc_length = der[5]
        if spc_length != len(der) - 6:
            return details
        try:
            spc = der[6:].decode("ascii")
        except UnicodeDecodeError:
            return details
        details["decoded"] = True
        details["spc"] = spc
        return details

    def key_usage_dict(self, value: x509.KeyUsage) -> dict[str, bool | None]:
        """Return key usage details.

        :param value: Key usage extension.
        :type value: x509.KeyUsage
        :return: Key usage details.
        :rtype: dict[str, bool | None]
        """

        encipher_only = None
        decipher_only = None
        if value.key_agreement:
            encipher_only = value.encipher_only
            decipher_only = value.decipher_only
        return {
            "digital_signature": value.digital_signature,
            "content_commitment": value.content_commitment,
            "key_encipherment": value.key_encipherment,
            "data_encipherment": value.data_encipherment,
            "key_agreement": value.key_agreement,
            "key_cert_sign": value.key_cert_sign,
            "crl_sign": value.crl_sign,
            "encipher_only": encipher_only,
            "decipher_only": decipher_only,
        }

    def authority_key_identifier_dict(
        self, value: x509.AuthorityKeyIdentifier
    ) -> dict[str, Any]:
        """Return authority key identifier details.

        :param value: Authority key identifier extension.
        :type value: x509.AuthorityKeyIdentifier
        :return: Authority key identifier details.
        :rtype: dict[str, Any]
        """

        key_identifier = None
        if value.key_identifier is not None:
            key_identifier = self.format_colon_hex(value.key_identifier)
        return {
            "key_identifier": key_identifier,
            "authority_cert_issuer": [
                self.general_name_dict(name)
                for name in value.authority_cert_issuer or []
            ],
            "authority_cert_serial_number": (
                str(value.authority_cert_serial_number)
                if value.authority_cert_serial_number is not None
                else None
            ),
        }

    def certificate_policy_dict(self, policy: x509.PolicyInformation) -> dict[str, Any]:
        """Return certificate policy details.

        :param policy: Certificate policy.
        :type policy: x509.PolicyInformation
        :return: Certificate policy details.
        :rtype: dict[str, Any]
        """

        return {
            "policy_identifier": self.oid_dict(policy.policy_identifier),
            "policy_qualifiers": [
                self.policy_qualifier_value(qualifier)
                for qualifier in policy.policy_qualifiers or []
            ],
        }

    def policy_qualifier_value(self, qualifier: Any) -> Any:
        """Return a JSON-safe policy qualifier value.

        :param qualifier: Policy qualifier.
        :type qualifier: Any
        :return: JSON-safe qualifier value.
        :rtype: Any
        """

        if isinstance(qualifier, str):
            return qualifier
        if isinstance(qualifier, x509.UserNotice):
            return {
                "explicit_text": qualifier.explicit_text,
                "notice_reference": str(qualifier.notice_reference),
            }
        return str(qualifier)

    def distribution_point_dict(self, point: x509.DistributionPoint) -> dict[str, Any]:
        """Return distribution point details.

        :param point: Distribution point.
        :type point: x509.DistributionPoint
        :return: Distribution point details.
        :rtype: dict[str, Any]
        """

        return {
            "full_name": [
                self.general_name_dict(name) for name in point.full_name or []
            ],
            "relative_name": (
                self.name_dict(point.relative_name)
                if point.relative_name is not None
                else None
            ),
            "reasons": (
                [reason.name for reason in point.reasons]
                if point.reasons is not None
                else None
            ),
            "crl_issuer": [
                self.general_name_dict(name) for name in point.crl_issuer or []
            ],
        }

    def access_description_dict(
        self, description: x509.AccessDescription
    ) -> dict[str, Any]:
        """Return authority information access details.

        :param description: Access description.
        :type description: x509.AccessDescription
        :return: Access description details.
        :rtype: dict[str, Any]
        """

        label = self.oid_name(description.access_method)
        if description.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
            label = "caIssuers"
        if description.access_method == AuthorityInformationAccessOID.OCSP:
            label = "OCSP"
        return {
            "access_method": {
                "oid": description.access_method.dotted_string,
                "name": label,
            },
            "access_location": self.general_name_dict(description.access_location),
        }

    def general_name_dict(self, name: x509.GeneralName) -> dict[str, Any]:
        """Return general name details.

        :param name: General name.
        :type name: x509.GeneralName
        :return: General name details.
        :rtype: dict[str, Any]
        """

        if isinstance(name, x509.DirectoryName):
            return {"type": "directory_name", "value": self.name_dict(name.value)}
        if isinstance(name, x509.RegisteredID):
            return {"type": "registered_id", "value": name.value.dotted_string}
        if isinstance(name, x509.OtherName):
            return {
                "type": "other_name",
                "oid": name.type_id.dotted_string,
                "value_base64": base64.b64encode(name.value).decode("ascii"),
            }
        value = getattr(name, "value", str(name))
        return {
            "type": name.__class__.__name__,
            "value": str(value),
        }

    def name_dict(
        self, name: x509.Name | x509.RelativeDistinguishedName
    ) -> dict[str, Any]:
        """Return X.509 name details.

        :param name: X.509 name.
        :type name: x509.Name | x509.RelativeDistinguishedName
        :return: Name details.
        :rtype: dict[str, Any]
        """

        return {
            "rfc4514": name.rfc4514_string(),
            "attributes": [
                {
                    "oid": attribute.oid.dotted_string,
                    "name": self.oid_name(attribute.oid),
                    "value": attribute.value,
                }
                for attribute in name
            ],
        }

    def public_key_dict(self, public_key: Any) -> dict[str, Any]:
        """Return public key details.

        :param public_key: Public key object.
        :type public_key: Any
        :return: Public key details.
        :rtype: dict[str, Any]
        """

        details: dict[str, Any] = {
            "type": public_key.__class__.__name__,
        }
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            details["type"] = "ec"
            details["curve"] = public_key.curve.name
            details["key_size"] = public_key.key_size
        elif isinstance(public_key, rsa.RSAPublicKey):
            details["type"] = "rsa"
            details["key_size"] = public_key.key_size
            details["public_exponent"] = public_key.public_numbers().e
        elif isinstance(public_key, dsa.DSAPublicKey):
            details["type"] = "dsa"
            details["key_size"] = public_key.key_size
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            details["type"] = "ed25519"
        elif isinstance(public_key, ed448.Ed448PublicKey):
            details["type"] = "ed448"
        return details

    def signature_algorithm_name(self, signed_object: Any) -> str | None:
        """Return a signature algorithm name.

        :param signed_object: Certificate or CSR.
        :type signed_object: Any
        :return: Algorithm name.
        :rtype: str | None
        """

        algorithm = signed_object.signature_hash_algorithm
        if algorithm is None:
            return None
        return algorithm.name

    def oid_dict(self, oid: ObjectIdentifier) -> dict[str, str]:
        """Return OID details.

        :param oid: Object identifier.
        :type oid: ObjectIdentifier
        :return: OID details.
        :rtype: dict[str, str]
        """

        return {"oid": oid.dotted_string, "name": self.oid_name(oid)}

    def oid_name(self, oid: ObjectIdentifier) -> str:
        """Return a readable OID name.

        :param oid: Object identifier.
        :type oid: ObjectIdentifier
        :return: OID name.
        :rtype: str
        """

        project_name = PROJECT_OID_NAMES.get(oid.dotted_string)
        if project_name is not None:
            return project_name
        return getattr(oid, "_name", oid.dotted_string)

    def extension_raw_base64(self, value: Any) -> str | None:
        """Return raw extension value bytes when available.

        :param value: Extension value.
        :type value: Any
        :return: Base64-encoded raw bytes.
        :rtype: str | None
        """

        if isinstance(value, x509.UnrecognizedExtension):
            return base64.b64encode(value.value).decode("ascii")
        public_bytes = getattr(value, "public_bytes", None)
        if public_bytes is None:
            return None
        try:
            return base64.b64encode(public_bytes()).decode("ascii")
        except (TypeError, ValueError):
            return None

    def format_colon_hex(self, value: bytes) -> str:
        """Format bytes as colon-separated uppercase hex.

        :param value: Binary value.
        :type value: bytes
        :return: Colon-separated hex string.
        :rtype: str
        """

        return ":".join(f"{byte:02X}" for byte in value)

    def iso_utc(self, value: Any) -> str:
        """Return an ISO timestamp with Z for UTC.

        :param value: Datetime value.
        :type value: Any
        :return: ISO timestamp.
        :rtype: str
        """

        return value.isoformat().replace("+00:00", "Z")

    def public_key_fingerprint_from_public_key(self, public_key: Any) -> str:
        """Return a SHA-256 public key fingerprint.

        :param public_key: Public key object.
        :type public_key: Any
        :return: STI-PA formatted fingerprint.
        :rtype: str
        """

        der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return FingerprintCalculator.format_digest(hashlib.sha256(der).digest())
