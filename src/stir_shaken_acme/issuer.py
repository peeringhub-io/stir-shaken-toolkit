"""Reusable STIR/SHAKEN ACME issuance workflow."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from acme_core import AcmeAccountState, AcmeClient

from stir_shaken_acme.certificates import CertificateDetails, ShakenCertificateManager
from stir_shaken_acme.errors import StirShakenError
from stir_shaken_acme.stipa import StipaClient, StipaToken
from stir_shaken_acme.tnauth import TnAuthList

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
    certificate_details: CertificateDetails


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
        self.acme_client = acme_client
        self.stipa_client = stipa_client
        self.certificate_manager = certificate_manager
        self.acme_poll_interval_seconds = acme_poll_interval_seconds
        self.acme_poll_timeout_seconds = acme_poll_timeout_seconds
        self.tn_auth_list_encoding = tn_auth_list_encoding

    def issue(
        self,
        spc: str,
        certificate_key_path: Path,
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
            "STIR/SHAKEN issuance: generating certificate key path=%s",
            certificate_key_path,
        )
        certificate_key = self.certificate_manager.generate_certificate_key(
            certificate_key_path
        )
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
        leaf_pem = self.certificate_manager.extract_leaf_pem(chain_pem)
        certificate = self.certificate_manager.parse_certificate(leaf_pem)
        LOGGER.debug("STIR/SHAKEN issuance: validating issued certificate")
        certificate_details = self.certificate_manager.validate_issued_certificate(
            certificate, certificate_key
        )
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
            certificate_key_path=certificate_key_path,
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
                "attempt=%s",
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
                raise StirShakenError(f"ACME order became {status}")
            time.sleep(self.acme_poll_interval_seconds)
            order = self.acme_client.post_as_get(order_url)
            attempt += 1
        raise StirShakenError(
            f"Timed out waiting for ACME order to become {desired_status}"
        )

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
