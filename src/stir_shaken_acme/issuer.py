"""Reusable STIR/SHAKEN ACME issuance workflow."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from acme_core import AcmeAccountState, AcmeClient
from acme_core.client import sanitize_json

from .certificates import CertificateDetails, ShakenCertificateManager
from .errors import ShakenValidationError, StirShakenError
from .stipa import StipaClient, StipaToken
from .tnauth import TnAuthList

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class StirShakenIssuanceResult:
    """Result of a STIR/SHAKEN ACME issuance transaction."""

    account_state: AcmeAccountState
    tn_auth_list: TnAuthList
    tn_auth_list_value: str
    stipa_token: StipaToken
    order_url: str
    order: dict[str, Any]
    authorization_url: str
    authorization: dict[str, Any]
    challenge: dict[str, Any]
    submitted_challenge: dict[str, Any]
    finalize_url: str
    finalized_order: dict[str, Any]
    valid_order: dict[str, Any]
    certificate_url: str
    certificate_key_path: Path
    csr_pem: bytes
    csr_der: bytes
    chain_pem: str
    leaf_pem: str
    certificate_details: CertificateDetails | None
    validation_error: str | None = None


class IssuanceValidationError(ShakenValidationError):
    """Raised when issuance reaches certificate download but validation fails."""

    def __init__(self, message: str, partial_result: StirShakenIssuanceResult) -> None:
        """Initialize the validation error with downloadable artifacts.

        :param message: Validation failure message.
        :type message: str
        :param partial_result: Partial issuance result with downloaded artifacts.
        :type partial_result: StirShakenIssuanceResult
        :return: None.
        :rtype: None
        """

        super().__init__(message)
        self.partial_result: StirShakenIssuanceResult = partial_result


class StirShakenIssuer:
    """Issue STIR/SHAKEN certificates through ACME and an Authority Token provider."""

    def __init__(
        self,
        acme_client: AcmeClient,
        stipa_client: StipaClient,
        certificate_manager: ShakenCertificateManager,
        acme_poll_interval_seconds: int = 5,
        acme_poll_timeout_seconds: int = 180,
        tn_auth_list_encoding: str = "base64url",
    ) -> None:
        self.acme_client: AcmeClient = acme_client
        self.stipa_client: StipaClient = stipa_client
        self.certificate_manager: ShakenCertificateManager = certificate_manager
        self.acme_poll_interval_seconds: int = acme_poll_interval_seconds
        self.acme_poll_timeout_seconds: int = acme_poll_timeout_seconds
        self.tn_auth_list_encoding: str = tn_auth_list_encoding

    def issue(
        self,
        spc: str,
        not_before: str | None = None,
        not_after: str | None = None,
    ) -> StirShakenIssuanceResult:
        """Run the STIR/SHAKEN ACME issuance sequence."""

        LOGGER.debug("STIR/SHAKEN issuance: preparing ACME account")
        account_state = self.acme_client.prepare_account()
        LOGGER.debug(
            "STIR/SHAKEN issuance: ACME account ready account_url=%s status=%s",
            account_state.account_url,
            account_state.status,
        )
        LOGGER.debug(
            "STIR/SHAKEN issuance: building TNAuthList encoding=%s spc_length=%s",
            self.tn_auth_list_encoding,
            len(spc),
        )
        tn_auth_list = TnAuthList(spc)
        tn_auth_list_value = tn_auth_list.encoded(self.tn_auth_list_encoding)
        LOGGER.debug(
            "STIR/SHAKEN issuance: using ACME account key for certificate CSR path=%s",
            account_state.account_key_path,
        )
        certificate_key = self.acme_client.require_private_key()
        LOGGER.debug("STIR/SHAKEN issuance: requesting STI-PA token")
        stipa_token = self.stipa_client.request_validated_token(
            tn_auth_list_value, account_state.account_key_fingerprint
        )
        LOGGER.debug(
            "STIR/SHAKEN issuance: STI-PA token validated jti=%s exp=%s",
            stipa_token.jti,
            stipa_token.exp,
        )
        LOGGER.debug("STIR/SHAKEN issuance: creating ACME order")
        order_url, order = self.acme_client.new_order(
            [{"type": "TNAuthList", "value": tn_auth_list_value}],
            not_before,
            not_after,
        )
        LOGGER.debug(
            "STIR/SHAKEN issuance: ACME order created order_url=%s status=%s",
            order_url,
            order.get("status"),
        )
        authorization_url = self.first_authorization_url(order)
        LOGGER.debug(
            "STIR/SHAKEN issuance: fetching authorization url=%s", authorization_url
        )
        authorization = self.acme_client.post_as_get(authorization_url)
        challenge = self.find_tkauth_challenge(authorization)
        LOGGER.debug(
            "STIR/SHAKEN issuance: submitting tkauth challenge url=%s status=%s",
            challenge.get("url"),
            challenge.get("status"),
        )
        submitted_challenge = self.acme_client.submit_challenge(
            str(challenge["url"]), {"atc": stipa_token.token}
        )
        LOGGER.debug(
            "STIR/SHAKEN issuance: challenge submitted status=%s",
            submitted_challenge.get("status"),
        )
        LOGGER.debug("STIR/SHAKEN issuance: polling order for ready")
        ready_order = self.poll_order(order_url, "ready")
        finalize_url = str(ready_order.get("finalize") or order.get("finalize"))
        LOGGER.debug("STIR/SHAKEN issuance: building certificate CSR")
        csr = self.certificate_manager.build_csr(certificate_key)
        csr_pem = self.certificate_manager.csr_pem(csr)
        csr_der = self.certificate_manager.csr_der(csr)
        LOGGER.debug("STIR/SHAKEN issuance: finalizing order url=%s", finalize_url)
        finalized_order = self.acme_client.finalize_order(finalize_url, csr_der)
        LOGGER.debug(
            "STIR/SHAKEN issuance: order finalized status=%s",
            finalized_order.get("status"),
        )
        LOGGER.debug("STIR/SHAKEN issuance: polling order for valid")
        valid_order = self.poll_order(order_url, "valid", finalized_order)
        certificate_url = str(valid_order["certificate"])
        LOGGER.debug(
            "STIR/SHAKEN issuance: downloading certificate url=%s", certificate_url
        )
        chain_pem = self.acme_client.download_certificate(certificate_url)
        LOGGER.debug(
            "STIR/SHAKEN issuance: certificate chain downloaded certificate_count=%s",
            chain_pem.count("-----BEGIN CERTIFICATE-----"),
        )
        leaf_pem = self.certificate_manager.extract_leaf_pem(chain_pem)
        certificate = self.certificate_manager.parse_certificate(leaf_pem)
        partial_result = StirShakenIssuanceResult(
            account_state=account_state,
            tn_auth_list=tn_auth_list,
            tn_auth_list_value=tn_auth_list_value,
            stipa_token=stipa_token,
            order_url=order_url,
            order=order,
            authorization_url=authorization_url,
            authorization=authorization,
            challenge=challenge,
            submitted_challenge=submitted_challenge,
            finalize_url=finalize_url,
            finalized_order=finalized_order,
            valid_order=valid_order,
            certificate_url=certificate_url,
            certificate_key_path=Path(account_state.account_key_path),
            csr_pem=csr_pem,
            csr_der=csr_der,
            chain_pem=chain_pem,
            leaf_pem=leaf_pem,
            certificate_details=None,
        )
        LOGGER.debug("STIR/SHAKEN issuance: validating issued certificate")
        try:
            certificate_details = self.certificate_manager.validate_issued_certificate(
                certificate, certificate_key
            )
        except ShakenValidationError as exc:
            raise IssuanceValidationError(
                str(exc),
                StirShakenIssuanceResult(
                    account_state=partial_result.account_state,
                    tn_auth_list=partial_result.tn_auth_list,
                    tn_auth_list_value=partial_result.tn_auth_list_value,
                    stipa_token=partial_result.stipa_token,
                    order_url=partial_result.order_url,
                    order=partial_result.order,
                    authorization_url=partial_result.authorization_url,
                    authorization=partial_result.authorization,
                    challenge=partial_result.challenge,
                    submitted_challenge=partial_result.submitted_challenge,
                    finalize_url=partial_result.finalize_url,
                    finalized_order=partial_result.finalized_order,
                    valid_order=partial_result.valid_order,
                    certificate_url=partial_result.certificate_url,
                    certificate_key_path=partial_result.certificate_key_path,
                    csr_pem=partial_result.csr_pem,
                    csr_der=partial_result.csr_der,
                    chain_pem=partial_result.chain_pem,
                    leaf_pem=partial_result.leaf_pem,
                    certificate_details=None,
                    validation_error=str(exc),
                ),
            ) from exc
        LOGGER.debug(
            "STIR/SHAKEN issuance completed: certificate_url=%s serial_number=%s",
            certificate_url,
            certificate_details.serial_number,
        )
        return StirShakenIssuanceResult(
            account_state=account_state,
            tn_auth_list=tn_auth_list,
            tn_auth_list_value=tn_auth_list_value,
            stipa_token=stipa_token,
            order_url=order_url,
            order=order,
            authorization_url=authorization_url,
            authorization=authorization,
            challenge=challenge,
            submitted_challenge=submitted_challenge,
            finalize_url=finalize_url,
            finalized_order=finalized_order,
            valid_order=valid_order,
            certificate_url=certificate_url,
            certificate_key_path=Path(account_state.account_key_path),
            csr_pem=csr_pem,
            csr_der=csr_der,
            chain_pem=chain_pem,
            leaf_pem=leaf_pem,
            certificate_details=certificate_details,
        )

    def poll_order(
        self,
        order_url: str,
        desired_status: str,
        current_order: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Poll an ACME order until it reaches the desired status."""

        deadline = time.time() + self.acme_poll_timeout_seconds
        order = current_order or self.acme_client.post_as_get(order_url)
        attempt = 1
        while time.time() < deadline:
            status = order.get("status")
            LOGGER.debug(
                "ACME order poll: url=%s desired_status=%s current_status=%s "
                + "attempt=%s",
                order_url,
                desired_status,
                status,
                attempt,
            )
            if status == desired_status:
                LOGGER.debug(
                    "ACME order poll reached desired status: url=%s status=%s",
                    order_url,
                    status,
                )
                return order
            if status in {"invalid", "revoked"}:
                self.raise_terminal_order_status(order_url, desired_status, order)
            time.sleep(self.acme_poll_interval_seconds)
            order = self.acme_client.post_as_get(order_url)
            attempt += 1
        raise StirShakenError(
            f"Timed out waiting for ACME order to become {desired_status}"
        )

    def raise_terminal_order_status(
        self,
        order_url: str,
        desired_status: str,
        order: dict[str, Any],
    ) -> None:
        """Raise an error with diagnostics for a terminal ACME order."""

        status = str(order.get("status", "unknown"))
        authorization_diagnostics = self.authorization_diagnostics(order)
        LOGGER.error(
            "ACME order became %s: url=%s desired_status=%s order=%s",
            status,
            order_url,
            desired_status,
            sanitize_json(order),
        )
        for authorization_url, authorization in authorization_diagnostics:
            LOGGER.error(
                "ACME authorization diagnostic: url=%s authorization=%s",
                authorization_url,
                sanitize_json(authorization),
            )
        summary = self.terminal_order_summary(order, authorization_diagnostics)
        raise StirShakenError(f"ACME order became {status}: {summary}")

    def authorization_diagnostics(
        self, order: dict[str, Any]
    ) -> list[tuple[str, dict[str, Any]]]:
        """Fetch authorization resources referenced by an order."""

        authorization_urls = order.get("authorizations")
        if not isinstance(authorization_urls, list):
            return []
        diagnostics: list[tuple[str, dict[str, Any]]] = []
        for authorization_url in authorization_urls:
            url = str(authorization_url)
            try:
                diagnostics.append((url, self.acme_client.post_as_get(url)))
            except Exception as exc:
                diagnostics.append((url, {"diagnostic_error": str(exc)}))
        return diagnostics

    def terminal_order_summary(
        self,
        order: dict[str, Any],
        authorization_diagnostics: list[tuple[str, dict[str, Any]]],
    ) -> str:
        """Build a compact terminal order diagnostic summary."""

        summary: dict[str, Any] = {
            "order_status": order.get("status"),
            "order_error": order.get("error"),
        }
        authorization_summary: list[dict[str, Any]] = []
        for authorization_url, authorization in authorization_diagnostics:
            authorization_summary.append(
                {
                    "url": authorization_url,
                    "status": authorization.get("status"),
                    "error": authorization.get("error"),
                    "challenge_errors": self.challenge_errors(authorization),
                    "diagnostic_error": authorization.get("diagnostic_error"),
                }
            )
        if authorization_summary:
            summary["authorizations"] = authorization_summary
        return sanitize_json(summary)

    def challenge_errors(self, authorization: dict[str, Any]) -> list[dict[str, Any]]:
        """Return challenge status and error details from an authorization."""

        challenges = authorization.get("challenges")
        if not isinstance(challenges, list):
            return []
        challenge_errors: list[dict[str, Any]] = []
        for challenge in challenges:
            if isinstance(challenge, dict):
                challenge_errors.append(
                    {
                        "type": challenge.get("type"),
                        "url": challenge.get("url"),
                        "status": challenge.get("status"),
                        "error": challenge.get("error"),
                    }
                )
        return challenge_errors

    def first_authorization_url(self, order: dict[str, Any]) -> str:
        """Return the first authorization URL from an ACME order."""

        authorizations = order.get("authorizations")
        if not isinstance(authorizations, list) or not authorizations:
            raise StirShakenError("ACME order missing authorizations")
        return str(authorizations[0])

    def find_tkauth_challenge(self, authorization: dict[str, Any]) -> dict[str, Any]:
        """Find a pending tkauth-01 ATC challenge."""

        challenges = authorization.get("challenges")
        if not isinstance(challenges, list):
            raise StirShakenError("ACME authorization missing challenges")
        for challenge in challenges:
            if (
                isinstance(challenge, dict)
                and challenge.get("type") == "tkauth-01"
                and challenge.get("tkauth-type") == "atc"
            ):
                if challenge.get("status") in {"pending", "processing"}:
                    return challenge
        raise StirShakenError(
            "ACME authorization missing pending tkauth-01 ATC challenge"
        )
