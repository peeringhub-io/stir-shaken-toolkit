"""STI-PA SPC token client and validation logic."""

from __future__ import annotations

import base64
import json
import logging
import time
from dataclasses import dataclass
from typing import Any

import jwt
import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .errors import StipaError

LOGGER = logging.getLogger(__name__)
SENSITIVE_KEYS = {
    "accessToken",
    "access_token",
    "Authorization",
    "authorization",
    "jwt",
    "password",
    "refreshToken",
    "refresh_token",
    "spcToken",
    "token",
}
SENSITIVE_KEY_NAMES = {key.lower() for key in SENSITIVE_KEYS}
SUMMARY_KEYS = (
    "status",
    "code",
    "error",
    "message",
    "description",
    "detail",
    "errors",
)
MAX_DIAGNOSTIC_JSON_LENGTH = 1000


@dataclass(frozen=True)
class StipaSettings:
    """STI-PA token API settings."""

    base_url: str
    user_id: str
    password: str
    sp_id: str
    expected_crl_url: str | None = None
    timeout_seconds: int = 30
    ca: bool = False
    minimum_token_lifetime_seconds: int = 180


@dataclass(frozen=True)
class StipaTokenPackage:
    """Validated STI-PA SPC token package and optional diagnostic material."""

    token: str
    crl_url: str
    x5u: str
    jti: str
    exp: int
    tn_auth_list_value: str
    fingerprint: str
    request_body: dict[str, Any]
    response_body: dict[str, Any]
    header: dict[str, Any]
    payload: dict[str, Any]
    signing_certificate_pem: str
    public_key_pem: bytes
    crl_bytes: bytes

    def token_summary(self) -> StipaToken:
        """Return a compact token summary.

        :return: Compact token details.
        :rtype: StipaToken
        """

        return StipaToken(
            token=self.token,
            crl_url=self.crl_url,
            x5u=self.x5u,
            jti=self.jti,
            exp=self.exp,
        )


@dataclass(frozen=True)
class StipaToken:
    """Validated STI-PA SPC token details."""

    token: str
    crl_url: str
    x5u: str
    jti: str
    exp: int


class StipaClient:
    """Client for STI-PA login, SPC token request, and token validation."""

    def __init__(self, settings: StipaSettings) -> None:
        self.settings: StipaSettings = settings
        self.session: requests.Session = requests.Session()

    def request_validated_token(
        self, tn_auth_list_value: str, fingerprint: str
    ) -> StipaToken:
        """Request and validate an STI-PA SPC token."""

        return self.request_validated_token_package(
            tn_auth_list_value, fingerprint
        ).token_summary()

    def request_validated_token_package(
        self, tn_auth_list_value: str, fingerprint: str
    ) -> StipaTokenPackage:
        """Request and validate an STI-PA SPC token package."""

        LOGGER.debug("STI-PA token package request started")
        access_token = self.extract_access_token(self.login())
        request_body = self.build_spc_token_request_body(
            tn_auth_list_value, fingerprint
        )
        response = self.request_spc_token(access_token, request_body)
        token = self.extract_spc_token(response)
        crl_url = self.extract_crl_url(response)
        LOGGER.debug("STI-PA token package response received: crl_url=%s", crl_url)
        return self.validate_spc_token_package(
            token, crl_url, tn_auth_list_value, fingerprint, request_body, response
        )

    def login(self) -> dict[str, Any]:
        """Authenticate with STI-PA."""

        url = f"{self.settings.base_url}/api/v1/auth/login"
        return self.post_json(
            url,
            {"accept": "application/json"},
            {"userId": self.settings.user_id, "password": self.settings.password},
            "STI-PA login",
        )

    def request_spc_token(
        self, access_token: str, request_body: dict[str, Any]
    ) -> dict[str, Any]:
        """Request an SPC token."""

        url = f"{self.settings.base_url}/api/v1/account/{self.settings.sp_id}/token"
        return self.post_json(
            url,
            {"accept": "application/json", "Authorization": access_token},
            request_body,
            "STI-PA SPC token",
        )

    def build_spc_token_request_body(
        self, tn_auth_list_value: str, fingerprint: str
    ) -> dict[str, Any]:
        """Build an SPC token request body."""

        return {
            "atc": {
                "tktype": "TNAuthList",
                "tkvalue": tn_auth_list_value,
                "ca": self.settings.ca,
                "fingerprint": fingerprint,
            },
        }

    def post_json(
        self,
        url: str,
        headers: dict[str, str],
        payload: dict[str, Any],
        context: str,
    ) -> dict[str, Any]:
        """POST JSON to STI-PA."""

        LOGGER.debug(
            "%s request: url=%s headers=%s payload=%s",
            context,
            url,
            sanitize_json(headers),
            sanitize_json(payload),
        )
        try:
            response = self.session.post(
                url,
                headers={**headers, "Content-Type": "application/json"},
                json=payload,
                timeout=self.settings.timeout_seconds,
            )
        except requests.RequestException as exc:
            raise StipaError(f"{context} failed for {url}: {exc}") from exc
        try:
            decoded = response.json() if response.content else {}
        except json.JSONDecodeError as exc:
            if response.status_code >= 400:
                diagnostic_response = response.text[:MAX_DIAGNOSTIC_JSON_LENGTH]
                raise StipaError(
                    f"{context} failed: http_status={response.status_code} "
                    + f"url={url} response={diagnostic_response}"
                ) from exc
            raise StipaError(
                f"{context} returned invalid JSON for {url}: {exc}"
            ) from exc
        if not isinstance(decoded, dict):
            raise StipaError(f"{context} response was not a JSON object for {url}")
        LOGGER.debug(
            "%s response: http_status=%s body=%s",
            context,
            response.status_code,
            sanitize_json(decoded),
        )
        if response.status_code >= 400:
            raise StipaError(self.stipa_error_message(context, url, response, decoded))
        if decoded.get("status") != "success":
            raise StipaError(self.stipa_error_message(context, url, response, decoded))
        return decoded

    def stipa_error_message(
        self,
        context: str,
        url: str,
        response: requests.Response,
        decoded: dict[str, Any],
    ) -> str:
        """Build a concise sanitized STI-PA error message."""

        parts = [
            f"{context} failed:",
            f"http_status={response.status_code}",
        ]
        for key in SUMMARY_KEYS:
            if key in decoded and is_present(decoded[key]):
                parts.append(f"{key}={json.dumps(sanitize_value(decoded[key]))}")
        parts.append(f"url={url}")
        if not any(key in decoded for key in SUMMARY_KEYS):
            parts.append(f"response={sanitize_json(decoded)}")
        return " ".join(parts)

    def validate_spc_token(
        self, token: str, crl_url: str, tn_auth_list_value: str, fingerprint: str
    ) -> StipaToken:
        """Validate SPC token signature and claims."""

        return self.validate_spc_token_package(
            token,
            crl_url,
            tn_auth_list_value,
            fingerprint,
            self.build_spc_token_request_body(tn_auth_list_value, fingerprint),
            {},
        ).token_summary()

    def validate_spc_token_package(
        self,
        token: str,
        crl_url: str,
        tn_auth_list_value: str,
        fingerprint: str,
        request_body: dict[str, Any],
        response_body: dict[str, Any],
    ) -> StipaTokenPackage:
        """Validate SPC token signature, claims, and supporting material."""

        LOGGER.debug("STI-PA SPC token validation started")
        header = self.decode_jwt_segment(token, 0)
        if header.get("alg") != "ES256":
            raise StipaError("SPC token alg must be ES256")
        x5u = header.get("x5u")
        if not isinstance(x5u, str) or not x5u:
            raise StipaError("SPC token header missing x5u")
        LOGGER.debug(
            "STI-PA SPC token header decoded: alg=%s x5u=%s", header.get("alg"), x5u
        )
        signing_certificate_pem = self.extract_first_certificate(
            self.download_text(x5u)
        )
        public_key_pem = self.extract_public_key_from_certificate(
            signing_certificate_pem
        )
        LOGGER.debug("STI-PA SPC token signing certificate loaded")
        try:
            payload = jwt.decode(
                token,
                public_key_pem,
                algorithms=["ES256"],
                options={"verify_aud": False},
            )
        except jwt.PyJWTError as exc:
            raise StipaError(f"SPC token signature validation failed: {exc}") from exc
        LOGGER.debug("STI-PA SPC token signature validated")
        atc = payload.get("atc")
        if not isinstance(atc, dict):
            raise StipaError("SPC token payload missing atc")
        if atc.get("tktype") != "TNAuthList":
            raise StipaError("SPC token tktype is not TNAuthList")
        if atc.get("tkvalue") != tn_auth_list_value:
            raise StipaError("SPC token tkvalue does not match TNAuthList")
        if atc.get("ca") is not False:
            raise StipaError("SPC token ca claim must be false")
        if atc.get("fingerprint") != fingerprint:
            raise StipaError("SPC token fingerprint does not match account key")
        exp = payload.get("exp")
        jti = payload.get("jti")
        if not isinstance(exp, int) or not isinstance(jti, str) or not jti:
            raise StipaError("SPC token missing exp or jti")
        if exp - int(time.time()) < self.settings.minimum_token_lifetime_seconds:
            raise StipaError(
                "SPC token lifetime is too short for ACME order completion"
            )
        if (
            self.settings.expected_crl_url is not None
            and crl_url != self.settings.expected_crl_url
        ):
            raise StipaError(f"STI-PA CRL URL mismatch: {crl_url}")
        LOGGER.debug(
            "STI-PA SPC token claims validated: jti=%s exp=%s crl_url=%s",
            jti,
            exp,
            crl_url,
        )
        crl_bytes = self.download_bytes(crl_url)
        LOGGER.debug("STI-PA SPC token validation completed")
        return StipaTokenPackage(
            token=token,
            crl_url=crl_url,
            x5u=x5u,
            jti=jti,
            exp=exp,
            tn_auth_list_value=tn_auth_list_value,
            fingerprint=fingerprint,
            request_body=request_body,
            response_body=response_body,
            header=header,
            payload=payload,
            signing_certificate_pem=signing_certificate_pem,
            public_key_pem=public_key_pem,
            crl_bytes=crl_bytes,
        )

    def extract_access_token(self, response: dict[str, Any]) -> str:
        """Extract STI-PA access token."""

        token = response.get("accessToken")
        if not isinstance(token, str) or not token:
            raise StipaError("STI-PA login response missing accessToken")
        return token

    def extract_spc_token(self, response: dict[str, Any]) -> str:
        """Extract SPC token."""

        token = response.get("token")
        if not isinstance(token, str) or not token:
            raise StipaError("STI-PA token response missing token")
        return token

    def extract_crl_url(self, response: dict[str, Any]) -> str:
        """Extract CRL URL."""

        crl_url = response.get("crl")
        if not isinstance(crl_url, str) or not crl_url:
            raise StipaError("STI-PA token response missing crl")
        return crl_url

    def download_text(self, url: str) -> str:
        """Download text."""

        try:
            LOGGER.debug(
                "STI-PA download request: url=%s accept=application/pkix-cert", url
            )
            response = self.session.get(
                url,
                headers={"accept": "application/pkix-cert"},
                timeout=self.settings.timeout_seconds,
            )
            LOGGER.debug(
                "STI-PA download response: url=%s http_status=%s content_type=%s "
                + "bytes=%s",
                url,
                response.status_code,
                response.headers.get("Content-Type", ""),
                len(response.content),
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise StipaError(f"STI-PA download failed for {url}: {exc}") from exc
        return response.text

    def download_bytes(self, url: str) -> bytes:
        """Download bytes."""

        try:
            LOGGER.debug(
                "STI-PA download request: url=%s accept=application/pkix-crl", url
            )
            response = self.session.get(
                url,
                headers={"accept": "application/pkix-crl"},
                timeout=self.settings.timeout_seconds,
            )
            LOGGER.debug(
                "STI-PA download response: url=%s http_status=%s content_type=%s "
                + "bytes=%s",
                url,
                response.status_code,
                response.headers.get("Content-Type", ""),
                len(response.content),
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise StipaError(f"STI-PA download failed for {url}: {exc}") from exc
        return response.content

    def decode_jwt_segment(self, token: str, index: int) -> dict[str, Any]:
        """Decode one JWT segment without validation."""

        segments = token.split(".")
        if len(segments) != 3:
            raise StipaError("SPC token must have three JWT segments")
        padding = "=" * ((4 - len(segments[index]) % 4) % 4)
        decoded = json.loads(
            base64.urlsafe_b64decode(f"{segments[index]}{padding}".encode("ascii"))
        )
        if not isinstance(decoded, dict):
            raise StipaError("JWT segment is not a JSON object")
        return decoded

    def extract_first_certificate(self, certificate_bundle: str) -> str:
        """Extract the first PEM certificate from a bundle."""

        start = certificate_bundle.find("-----BEGIN CERTIFICATE-----")
        end = certificate_bundle.find("-----END CERTIFICATE-----", start)
        if start < 0 or end < 0:
            raise StipaError("No PEM certificate found in STI-PA x5u bundle")
        end += len("-----END CERTIFICATE-----")
        return f"{certificate_bundle[start:end]}\n"

    def extract_public_key_from_certificate(self, certificate_pem: str) -> bytes:
        """Extract a PEM public key from a PEM certificate."""

        certificate = x509.load_pem_x509_certificate(certificate_pem.encode("utf-8"))
        return certificate.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )


def sanitize_value(value: Any) -> Any:
    """Return a sanitized diagnostic value."""

    if isinstance(value, dict):
        return {
            key: (
                "[redacted]"
                if str(key).lower() in SENSITIVE_KEY_NAMES
                else sanitize_value(child)
            )
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [sanitize_value(item) for item in value]
    return value


def is_present(value: Any) -> bool:
    """Return whether a diagnostic value has usable content."""

    return value is not None and value != ""


def sanitize_json(value: Any) -> str:
    """Return bounded sanitized JSON for diagnostics."""

    return json.dumps(
        sanitize_value(value),
        sort_keys=True,
        default=str,
    )[:MAX_DIAGNOSTIC_JSON_LENGTH]
