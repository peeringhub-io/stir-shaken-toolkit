"""Provider-neutral RFC 8555 ACME client."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import requests
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

from acme_core import base64url
from acme_core.errors import AcmeBadNonceError, AcmeClientError, AcmeProtocolError
from acme_core.keys import AcmeKeyManager

ACME_BAD_NONCE_TYPE = "urn:ietf:params:acme:error:badNonce"
JsonObject = dict[str, Any]
EmptyPayloadSigningMode = Literal["standard", "protected_only"]
LOGGER = logging.getLogger(__name__)
SENSITIVE_KEYS = {
    "atc",
    "authorization",
    "jws",
    "payload",
    "signature",
    "token",
}
SENSITIVE_KEY_NAMES = {key.lower() for key in SENSITIVE_KEYS}
MAX_DIAGNOSTIC_JSON_LENGTH = 1000


@dataclass(frozen=True)
class AcmeProfilePolicy:
    """ACME provider behavior policy.

    :param empty_payload_signing_mode: JWS signing mode for POST-as-GET payloads.
    :type empty_payload_signing_mode: EmptyPayloadSigningMode
    :param include_jwk_kid: Include the local display key ID inside new-account JWKs.
    :type include_jwk_kid: bool
    :param required_directory_fields: Required directory fields.
    :type required_directory_fields: tuple[str, ...]
    :param certificate_content_types: Accepted certificate response content types.
    :type certificate_content_types: tuple[str, ...]
    """

    empty_payload_signing_mode: EmptyPayloadSigningMode = "standard"
    include_jwk_kid: bool = False
    required_directory_fields: tuple[str, ...] = ("newNonce", "newAccount", "newOrder")
    certificate_content_types: tuple[str, ...] = (
        "application/pem-certificate-chain",
        "application/pem",
    )


@dataclass(frozen=True)
class AcmeProfile:
    """Named ACME profile.

    :param name: Profile name.
    :type name: str
    :param policy: Provider behavior policy.
    :type policy: AcmeProfilePolicy
    """

    name: str = "rfc8555"
    policy: AcmeProfilePolicy = field(default_factory=AcmeProfilePolicy)


@dataclass
class AcmeAccountState:
    """Persisted ACME account state.

    :param profile: ACME profile name.
    :type profile: str
    :param acme_base_url: ACME directory URL.
    :type acme_base_url: str
    :param account_url: ACME account URL.
    :type account_url: str
    :param orders_url: ACME orders URL.
    :type orders_url: str | None
    :param kid: Human-readable local key identifier.
    :type kid: str
    :param account_key_path: Account key path.
    :type account_key_path: str
    :param account_key_fingerprint: SHA256 account public-key fingerprint.
    :type account_key_fingerprint: str
    :param created_at: Creation timestamp.
    :type created_at: str
    :param last_verified_at: Last verification timestamp.
    :type last_verified_at: str | None
    :param status: ACME account status.
    :type status: str
    """

    profile: str
    acme_base_url: str
    account_url: str
    orders_url: str | None
    kid: str
    account_key_path: str
    account_key_fingerprint: str
    created_at: str
    last_verified_at: str | None
    status: str


class AcmeClient:
    """Client for RFC 8555 ACME account and order operations."""

    def __init__(
        self,
        base_url: str,
        key_manager: AcmeKeyManager,
        state_path: Path,
        profile: AcmeProfile | None = None,
        timeout_seconds: int = 30,
        bad_nonce_retries: int = 2,
    ) -> None:
        self.base_url = base_url
        self.key_manager = key_manager
        self.state_path = state_path
        self.profile = profile or AcmeProfile()
        self.timeout_seconds = timeout_seconds
        self.bad_nonce_retries = bad_nonce_retries
        self.session = requests.Session()
        self.directory: dict[str, str] = {}
        self.nonce: str | None = None
        self.account_state: AcmeAccountState | None = None
        self.private_key: EllipticCurvePrivateKey | None = None

    def prepare_account(
        self, account_payload: JsonObject | None = None
    ) -> AcmeAccountState:
        """Load or create an ACME account.

        :param account_payload: Optional new-account payload.
        :type account_payload: JsonObject | None
        :return: Account state.
        :rtype: AcmeAccountState
        """

        LOGGER.debug(
            "ACME account preparation started: base_url=%s profile=%s "
            "state_path=%s key_path=%s",
            self.base_url,
            self.profile.name,
            self.state_path,
            self.key_manager.key_path,
        )
        self.private_key = self.key_manager.load_or_create()
        self.discover_directory()
        self.fetch_nonce()
        if self.state_path.exists():
            LOGGER.debug("ACME account state exists; verifying account")
            state = self.load_state()
            self.account_state = state
            account_object = self.post_as_get(state.account_url)
            status = account_object.get("status", state.status)
            if status in {"deactivated", "revoked"}:
                raise AcmeClientError(f"ACME account status is {status}")
            state.status = str(status)
            state.last_verified_at = now_utc()
            self.save_state(state)
            LOGGER.debug(
                "ACME account verified: account_url=%s status=%s",
                state.account_url,
                state.status,
            )
            return state
        LOGGER.debug("ACME account state missing; creating account")
        state = self.create_account(account_payload)
        self.account_state = state
        self.save_state(state)
        LOGGER.debug(
            "ACME account created: account_url=%s status=%s",
            state.account_url,
            state.status,
        )
        return state

    def discover_directory(self) -> dict[str, str]:
        """Discover ACME directory URLs.

        :return: Directory object.
        :rtype: dict[str, str]
        """

        try:
            LOGGER.debug("ACME directory request: method=GET url=%s", self.base_url)
            response = self.session.get(self.base_url, timeout=self.timeout_seconds)
            LOGGER.debug(
                "ACME directory response: http_status=%s content_type=%s",
                response.status_code,
                response.headers.get("Content-Type", ""),
            )
            response.raise_for_status()
            directory = response.json()
        except (requests.RequestException, json.JSONDecodeError) as exc:
            raise AcmeClientError(f"ACME directory discovery failed: {exc}") from exc
        required_urls = set(self.profile.policy.required_directory_fields)
        missing = required_urls.difference(directory)
        if missing:
            raise AcmeProtocolError(
                f"ACME directory missing required URLs: {sorted(missing)}"
            )
        self.directory = {key: str(value) for key, value in directory.items()}
        LOGGER.debug("ACME directory discovered: keys=%s", sorted(self.directory))
        return self.directory

    def fetch_nonce(self) -> str:
        """Fetch a fresh ACME nonce.

        :return: Replay nonce.
        :rtype: str
        """

        url = self.directory_url("newNonce")
        try:
            LOGGER.debug("ACME nonce request: method=HEAD url=%s", url)
            response = self.session.head(url, timeout=self.timeout_seconds)
            if response.status_code == 405:
                LOGGER.debug("ACME nonce HEAD not allowed; retrying with GET")
                response = self.session.get(url, timeout=self.timeout_seconds)
            LOGGER.debug(
                "ACME nonce response: http_status=%s replay_nonce_present=%s",
                response.status_code,
                response.headers.get("Replay-Nonce") is not None,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise AcmeClientError(f"ACME nonce request failed: {exc}") from exc
        nonce = response.headers.get("Replay-Nonce")
        if not nonce:
            raise AcmeProtocolError("ACME nonce response did not include Replay-Nonce")
        self.nonce = nonce
        LOGGER.debug("ACME nonce stored")
        return nonce

    def create_account(self, payload: JsonObject | None) -> AcmeAccountState:
        """Create a new ACME account.

        :param payload: New-account payload.
        :type payload: JsonObject | None
        :return: Created account state.
        :rtype: AcmeAccountState
        """

        private_key = self.require_private_key()
        LOGGER.debug(
            "ACME account creation request: url=%s payload=%s",
            self.directory_url("newAccount"),
            sanitize_json(payload or {}),
        )
        response = self.signed_post_raw(
            url=self.directory_url("newAccount"),
            payload=payload,
            account_url=None,
            jwk=self.key_manager.jwk(
                private_key, include_kid=self.profile.policy.include_jwk_kid
            ),
        )
        account_url = response.headers.get("Location")
        if not account_url:
            raise AcmeProtocolError("ACME account creation did not return Location")
        account_object = self.decode_json_response(response)
        LOGGER.debug(
            "ACME account creation response: location=%s status=%s",
            account_url,
            account_object.get("status", "valid"),
        )
        return AcmeAccountState(
            profile=self.profile.name,
            acme_base_url=self.base_url,
            account_url=account_url,
            orders_url=account_object.get("orders"),
            kid=self.key_manager.kid,
            account_key_path=str(self.key_manager.key_path),
            account_key_fingerprint=self.key_manager.public_key_fingerprint(
                private_key
            ),
            created_at=now_utc(),
            last_verified_at=now_utc(),
            status=str(account_object.get("status", "valid")),
        )

    def new_order(
        self,
        identifiers: list[JsonObject],
        not_before: str | None = None,
        not_after: str | None = None,
    ) -> tuple[str, JsonObject]:
        """Create an ACME certificate order.

        :param identifiers: ACME order identifiers.
        :type identifiers: list[JsonObject]
        :param not_before: Optional RFC 3339 notBefore timestamp.
        :type not_before: str | None
        :param not_after: Optional RFC 3339 notAfter timestamp.
        :type not_after: str | None
        :return: Order URL and order object.
        :rtype: tuple[str, JsonObject]
        """

        payload: JsonObject = {"identifiers": identifiers}
        if not_before:
            payload["notBefore"] = not_before
        if not_after:
            payload["notAfter"] = not_after
        LOGGER.debug(
            "ACME newOrder request: identifiers=%s not_before=%s not_after=%s",
            sanitize_json(identifiers),
            not_before,
            not_after,
        )
        response = self.signed_post_raw(self.directory_url("newOrder"), payload)
        order_url = response.headers.get("Location")
        if not order_url:
            raise AcmeProtocolError("ACME newOrder response did not return Location")
        order_object = self.decode_json_response(response)
        LOGGER.debug(
            "ACME newOrder response: order_url=%s status=%s",
            order_url,
            order_object.get("status"),
        )
        return order_url, order_object

    def post_as_get(self, url: str) -> JsonObject:
        """Send an ACME POST-as-GET request.

        :param url: ACME resource URL.
        :type url: str
        :return: Decoded response JSON.
        :rtype: JsonObject
        """

        LOGGER.debug("ACME POST-as-GET request: url=%s", url)
        return self.decode_json_response(self.signed_post_raw(url, None))

    def submit_challenge(
        self, challenge_url: str, response_payload: JsonObject
    ) -> JsonObject:
        """Submit an ACME challenge response.

        :param challenge_url: Challenge URL.
        :type challenge_url: str
        :param response_payload: Challenge response payload.
        :type response_payload: JsonObject
        :return: Challenge response object.
        :rtype: JsonObject
        """

        LOGGER.debug(
            "ACME challenge submission request: url=%s payload=%s",
            challenge_url,
            sanitize_json(response_payload),
        )
        return self.decode_json_response(
            self.signed_post_raw(challenge_url, response_payload)
        )

    def finalize_order(self, finalize_url: str, csr_der: bytes) -> JsonObject:
        """Finalize an ACME order with a DER CSR.

        :param finalize_url: Finalize URL.
        :type finalize_url: str
        :param csr_der: DER-encoded CSR.
        :type csr_der: bytes
        :return: Finalize response object.
        :rtype: JsonObject
        """

        LOGGER.debug(
            "ACME finalize request: url=%s csr_der_bytes=%s",
            finalize_url,
            len(csr_der),
        )
        return self.decode_json_response(
            self.signed_post_raw(finalize_url, {"csr": base64url.encode(csr_der)})
        )

    def download_certificate(self, certificate_url: str) -> str:
        """Download a PEM certificate chain.

        :param certificate_url: Certificate URL.
        :type certificate_url: str
        :return: PEM certificate chain.
        :rtype: str
        """

        LOGGER.debug("ACME certificate download request: url=%s", certificate_url)
        response = self.signed_post_raw(certificate_url, None)
        content_type = response.headers.get("Content-Type", "")
        if not any(
            accepted in content_type
            for accepted in self.profile.policy.certificate_content_types
        ):
            raise AcmeProtocolError(
                f"Unexpected certificate content type: {content_type}"
            )
        LOGGER.debug(
            "ACME certificate download response: content_type=%s bytes=%s",
            content_type,
            len(response.content),
        )
        return response.text

    def signed_post_raw(
        self,
        url: str,
        payload: JsonObject | None,
        account_url: str | None = None,
        jwk: dict[str, str] | None = None,
    ) -> requests.Response:
        """Send a signed ACME POST and return the raw response."""

        last_error: Exception | None = None
        for attempt in range(self.bad_nonce_retries + 1):
            try:
                LOGGER.debug(
                    "ACME signed POST attempt: url=%s attempt=%s",
                    url,
                    attempt + 1,
                )
                return self._signed_post_once(url, payload, account_url, jwk)
            except AcmeBadNonceError as exc:
                last_error = exc
                LOGGER.debug(
                    "ACME badNonce received; fetching a new nonce: url=%s attempt=%s",
                    url,
                    attempt + 1,
                )
                self.fetch_nonce()
        raise AcmeClientError(f"ACME POST failed after badNonce retries: {last_error}")

    def _signed_post_once(
        self,
        url: str,
        payload: JsonObject | None,
        account_url: str | None,
        jwk: dict[str, str] | None,
    ) -> requests.Response:
        private_key = self.require_private_key()
        nonce = self.nonce or self.fetch_nonce()
        protected: JsonObject = {"alg": "ES256", "nonce": nonce, "url": url}
        if jwk is not None:
            protected["jwk"] = jwk
        else:
            protected["kid"] = account_url or self.require_account_url()
        jws = self.key_manager.sign_jws(
            private_key,
            protected,
            payload,
            empty_payload_signing_mode=self.profile.policy.empty_payload_signing_mode,
        )
        try:
            LOGGER.debug(
                "ACME signed POST request: url=%s protected=%s payload=%s",
                url,
                sanitize_json(protected),
                summarize_payload(payload),
            )
            response = self.session.post(
                url,
                headers={"Content-Type": "application/jose+json"},
                json=jws,
                timeout=self.timeout_seconds,
            )
        except requests.RequestException as exc:
            raise AcmeClientError(f"ACME POST failed for {url}: {exc}") from exc
        replay_nonce = response.headers.get("Replay-Nonce")
        if replay_nonce:
            self.nonce = replay_nonce
        LOGGER.debug(
            "ACME signed POST response: url=%s http_status=%s content_type=%s "
            "location=%s replay_nonce_present=%s",
            url,
            response.status_code,
            response.headers.get("Content-Type", ""),
            response.headers.get("Location"),
            replay_nonce is not None,
        )
        if response.status_code >= 400:
            self.raise_for_acme_error(response)
        return response

    def raise_for_acme_error(self, response: requests.Response) -> None:
        """Raise a sanitized ACME exception for an error response."""

        try:
            error_object = response.json()
        except json.JSONDecodeError:
            error_object = {"detail": response.text[:500]}
        if error_object.get("type") == ACME_BAD_NONCE_TYPE:
            raise AcmeBadNonceError(str(error_object.get("detail", "bad nonce")))
        raise AcmeClientError(
            f"ACME request failed: status={response.status_code} error={sanitize_json(error_object)}"
        )

    def load_state(self) -> AcmeAccountState:
        """Load persisted account state.

        :return: Account state.
        :rtype: AcmeAccountState
        """

        LOGGER.debug("ACME account state load: path=%s", self.state_path)
        return AcmeAccountState(**json.loads(self.state_path.read_text()))

    def save_state(self, state: AcmeAccountState) -> None:
        """Persist account state atomically."""

        self.state_path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        temporary_path = self.state_path.with_name(f".{self.state_path.name}.tmp")
        LOGGER.debug(
            "ACME account state save: path=%s temporary_path=%s status=%s",
            self.state_path,
            temporary_path,
            state.status,
        )
        temporary_path.write_text(
            json.dumps(asdict(state), indent=2, sort_keys=True) + "\n"
        )
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, self.state_path)

    def directory_url(self, key: str) -> str:
        """Return a discovered directory URL."""

        if key not in self.directory:
            raise AcmeProtocolError(f"ACME directory URL is missing: {key}")
        return self.directory[key]

    def require_private_key(self) -> EllipticCurvePrivateKey:
        """Return the loaded private key."""

        if self.private_key is None:
            LOGGER.debug("ACME account key not loaded; loading or creating key")
            self.private_key = self.key_manager.load_or_create()
        return self.private_key

    def require_account_url(self) -> str:
        """Return the loaded account URL."""

        if self.account_state is not None:
            return self.account_state.account_url
        if self.state_path.exists():
            LOGGER.debug("ACME account URL requested; loading state")
            self.account_state = self.load_state()
            return self.account_state.account_url
        raise AcmeProtocolError("ACME account URL is not available")

    def decode_json_response(self, response: requests.Response) -> JsonObject:
        """Decode a JSON response."""

        try:
            decoded = response.json() if response.content else {}
        except json.JSONDecodeError as exc:
            raise AcmeProtocolError(f"ACME JSON response failed: {exc}") from exc
        if not isinstance(decoded, dict):
            raise AcmeProtocolError("ACME JSON response was not an object")
        return decoded


def now_utc() -> str:
    """Return the current UTC timestamp."""

    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sanitize_json(value: Any) -> str:
    """Return bounded JSON text for diagnostics."""

    return json.dumps(
        sanitize_value(value),
        sort_keys=True,
        default=str,
    )[:MAX_DIAGNOSTIC_JSON_LENGTH]


def sanitize_value(value: Any) -> Any:
    """Return a redacted diagnostic value."""

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


def summarize_payload(payload: JsonObject | None) -> str:
    """Return a safe ACME payload summary."""

    if payload is None:
        return "POST-as-GET"
    if "csr" in payload:
        return sanitize_json({"csr": f"[base64url bytes={len(str(payload['csr']))}]"})
    return sanitize_json(payload)
