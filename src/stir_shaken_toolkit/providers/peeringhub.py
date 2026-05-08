"""Peeringhub STIR/SHAKEN ACME provider profile."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from acme_core import (
    AcmeAccountState,
    AcmeClient,
    AcmeKeyManager,
    AcmeProfile,
    AcmeProfilePolicy,
)
from stir_shaken_acme import (
    ShakenCertificateManager,
    ShakenCertificatePolicy,
    ShakenSubject,
    StipaClient,
    StipaSettings,
    StirShakenIssuanceResult,
    StirShakenIssuer,
)

PEERINGHUB_ACME_URLS = {
    "production": "https://stica.peeringhub.io/acme",
    "staging": "https://stica-dev.peeringhub.io/acme",
}
PEERINGHUB_STIPA_URLS = {
    "production": "https://authenticate-api.iconectiv.com",
    "staging": "https://authenticate-api-stg.iconectiv.com",
}
PEERINGHUB_STIPA_CRL_URLS = {
    "production": "https://authenticate-api.iconectiv.com/download/v1/crl",
    "staging": "https://authenticate-api-stg.iconectiv.com/download/v1/crl",
}


@dataclass(frozen=True)
class PeeringhubProfile:
    """Peeringhub ACME/STI-PA profile."""

    environment: str
    acme_base_url: str
    stipa_base_url: str
    stipa_crl_url: str
    tn_auth_list_encoding: str = "base64"

    @classmethod
    def for_environment(cls, environment: str) -> PeeringhubProfile:
        """Return default Peeringhub profile values for an environment."""

        return cls(
            environment=environment,
            acme_base_url=PEERINGHUB_ACME_URLS[environment],
            stipa_base_url=PEERINGHUB_STIPA_URLS[environment],
            stipa_crl_url=PEERINGHUB_STIPA_CRL_URLS[environment],
        )

    def acme_profile(self) -> AcmeProfile:
        """Return the ACME behavior profile for Peeringhub."""

        return AcmeProfile(
            name=f"peeringhub-{self.environment}",
            policy=AcmeProfilePolicy(
                empty_payload_signing_mode="protected_only",
                include_jwk_kid=True,
                certificate_content_types=(
                    "application/pem-certificate-chain",
                    "application/pem",
                    "pem-certificate-chain",
                ),
            ),
        )


class PeeringhubIssuer:
    """High-level Peeringhub issuer for Python callers and CLIs."""

    def __init__(
        self,
        profile: PeeringhubProfile,
        acme_client: AcmeClient,
        stipa_client: StipaClient,
        certificate_manager: ShakenCertificateManager,
        acme_poll_interval_seconds: int = 5,
        acme_poll_timeout_seconds: int = 180,
    ) -> None:
        self.profile = profile
        self.acme_client = acme_client
        self.stipa_client = stipa_client
        self.certificate_manager = certificate_manager
        self.issuer = StirShakenIssuer(
            acme_client=acme_client,
            stipa_client=stipa_client,
            certificate_manager=certificate_manager,
            acme_poll_interval_seconds=acme_poll_interval_seconds,
            acme_poll_timeout_seconds=acme_poll_timeout_seconds,
            tn_auth_list_encoding=profile.tn_auth_list_encoding,
        )

    @classmethod
    def build(
        cls,
        profile: PeeringhubProfile,
        account_key_path: Path,
        account_state_path: Path,
        acme_kid: str,
        stipa_settings: StipaSettings,
        certificate_policy: ShakenCertificatePolicy,
        acme_timeout_seconds: int = 30,
        acme_bad_nonce_retries: int = 2,
        acme_poll_interval_seconds: int = 5,
        acme_poll_timeout_seconds: int = 180,
    ) -> PeeringhubIssuer:
        """Build a Peeringhub issuer from explicit settings."""

        acme_client = AcmeClient(
            base_url=profile.acme_base_url,
            key_manager=AcmeKeyManager(account_key_path, acme_kid),
            state_path=account_state_path,
            profile=profile.acme_profile(),
            timeout_seconds=acme_timeout_seconds,
            bad_nonce_retries=acme_bad_nonce_retries,
        )
        return cls(
            profile=profile,
            acme_client=acme_client,
            stipa_client=StipaClient(stipa_settings),
            certificate_manager=ShakenCertificateManager(certificate_policy),
            acme_poll_interval_seconds=acme_poll_interval_seconds,
            acme_poll_timeout_seconds=acme_poll_timeout_seconds,
        )

    @classmethod
    def for_account_status(
        cls,
        environment: str,
        acme_base_url: str,
        account_key_path: Path,
        account_state_path: Path,
        acme_kid: str,
        timeout_seconds: int = 30,
        bad_nonce_retries: int = 2,
    ) -> PeeringhubIssuer:
        """Build a Peeringhub issuer sufficient for account status checks."""

        profile = PeeringhubProfile.for_environment(environment)
        profile = PeeringhubProfile(
            environment=environment,
            acme_base_url=acme_base_url,
            stipa_base_url=profile.stipa_base_url,
            stipa_crl_url=profile.stipa_crl_url,
            tn_auth_list_encoding=profile.tn_auth_list_encoding,
        )
        stipa_settings = StipaSettings(
            base_url=profile.stipa_base_url,
            user_id="unused",
            password="unused",
            sp_id="unused",
            expected_crl_url=profile.stipa_crl_url,
        )
        certificate_policy = ShakenCertificatePolicy(
            subject=ShakenSubject(
                country="US",
                state="unused",
                locality="unused",
                organization="unused",
                common_name="SHAKEN unused",
            ),
            tn_auth_list_der=b"",
            expected_crl_url=profile.stipa_crl_url,
            critical_days=1,
        )
        return cls.build(
            profile=profile,
            account_key_path=account_key_path,
            account_state_path=account_state_path,
            acme_kid=acme_kid,
            stipa_settings=stipa_settings,
            certificate_policy=certificate_policy,
            acme_timeout_seconds=timeout_seconds,
            acme_bad_nonce_retries=bad_nonce_retries,
        )

    def prepare_account(self) -> AcmeAccountState:
        """Prepare and verify the ACME account."""

        return self.acme_client.prepare_account()

    def issue(
        self,
        spc: str,
        certificate_key_path: Path,
        not_before: str | None = None,
        not_after: str | None = None,
    ) -> StirShakenIssuanceResult:
        """Issue a Peeringhub STIR/SHAKEN certificate."""

        return self.issuer.issue(spc, certificate_key_path, not_before, not_after)
