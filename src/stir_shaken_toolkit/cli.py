"""Command-line interface for STIR/SHAKEN toolkit operations."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from textwrap import dedent
from typing import Any

import argcomplete
from argcomplete.completers import DirectoriesCompleter, FilesCompleter

from stir_shaken_acme import (
    FingerprintCalculator,
    ShakenCertificateManager,
    ShakenCertificatePolicy,
    ShakenSubject,
    StipaClient,
    StipaSettings,
    StipaTokenPackage,
    StirShakenIssuanceResult,
    TnAuthList,
)
from stir_shaken_acme.errors import StirShakenError
from stir_shaken_toolkit.config import CliValueResolver
from stir_shaken_toolkit.providers.peeringhub import (
    PEERINGHUB_STIPA_URLS,
    PeeringhubIssuer,
    PeeringhubProfile,
)

SUCCESS_EXIT_CODE = 0
FAILURE_EXIT_CODE = 1
DEFAULT_TIMEOUT_SECONDS = 30
DEFAULT_CRITICAL_DAYS = 21
DEFAULT_POLL_INTERVAL_SECONDS = 5
DEFAULT_POLL_TIMEOUT_SECONDS = 180
DEFAULT_BAD_NONCE_RETRIES = 2
DEFAULT_STIPA_ENVIRONMENT = "production"
DEFAULT_SHAKEN_KEY_OUT = "shaken.key"
DEFAULT_SHAKEN_CSR_PEM_OUT = "shaken.csr"
LOGGER = logging.getLogger(__name__)
CERTIFICATE_EXTENSIONS = (".crt", ".pem")
CSR_EXTENSIONS = (".csr", ".pem")
KEY_EXTENSIONS = (".key", ".pem")
JSON_EXTENSIONS = (".json",)
YAML_EXTENSIONS = (".yaml", ".yml")


class StirShakenToolkitCli:
    """STIR/SHAKEN toolkit command-line interface."""

    def run(self, argv: list[str] | None = None) -> int:
        """Run the CLI.

        :param argv: Optional argument vector.
        :type argv: list[str] | None
        :return: Process exit code.
        :rtype: int
        """

        args = self.parse_args(argv)
        logging.basicConfig(
            level=logging.DEBUG if args.debug else logging.INFO,
            format="%(levelname)s %(message)s",
        )
        LOGGER.debug(
            "CLI invocation: command=%s config=%s debug=%s",
            args.command,
            args.config,
            args.debug,
        )
        try:
            resolver = CliValueResolver(Path(args.config) if args.config else None)
            LOGGER.debug(
                "CLI value resolver initialized: config_path=%s config_keys=%s",
                resolver.config_path,
                sorted(resolver.config),
            )
            return self.run_command(args, resolver)
        except (OSError, RuntimeError) as exc:
            logging.error("%s", exc)
            return FAILURE_EXIT_CODE

    def run_command(self, args: argparse.Namespace, resolver: CliValueResolver) -> int:
        """Dispatch a parsed command.

        :param args: Parsed arguments.
        :type args: argparse.Namespace
        :param resolver: Config and environment resolver.
        :type resolver: CliValueResolver
        :return: Process exit code.
        :rtype: int
        """

        if args.command == "tnauth":
            return self.run_tnauth(args, resolver)
        if args.command == "fingerprint":
            return self.run_fingerprint(args, resolver)
        if args.command == "spc-token":
            return self.run_spc_token(args, resolver)
        if args.command == "validate-cert":
            return self.run_validate_cert(args, resolver)
        if args.command == "peeringhub-account-status":
            return self.run_peeringhub_account_status(args, resolver)
        if args.command == "peeringhub-issue":
            return self.run_peeringhub_issue(args, resolver)
        if args.command == "csr":
            return self.run_csr(args, resolver)
        raise StirShakenError(f"Unsupported command: {args.command}")

    def run_tnauth(self, args: argparse.Namespace, resolver: CliValueResolver) -> int:
        """Run the local TNAuthList encoder."""

        spc = resolver.required_string(
            args.spc, "stipa_spc", "STIPA_SPC", "--spc or STIPA_SPC"
        )
        LOGGER.debug(
            "TNAuthList command: encoding=%s spc_length=%s",
            args.encoding,
            len(spc),
        )
        tn_auth_list = TnAuthList(spc)
        print(tn_auth_list.encoded(args.encoding))
        LOGGER.debug("TNAuthList command completed")
        return SUCCESS_EXIT_CODE

    def run_fingerprint(
        self, args: argparse.Namespace, resolver: CliValueResolver
    ) -> int:
        """Run the local fingerprint calculator."""

        source_count = sum(
            [
                args.certificate is not None,
                args.csr is not None,
                args.private_key is not None,
                bool(args.acme_account_key),
            ]
        )
        if source_count != 1:
            raise StirShakenError(
                "Use exactly one of --certificate, --csr, --private-key, "
                "or --acme-account-key"
            )
        if args.certificate is not None:
            LOGGER.debug(
                "Fingerprint command: source=certificate path=%s", args.certificate
            )
            print(FingerprintCalculator.from_certificate(Path(args.certificate)))
            LOGGER.debug("Fingerprint command completed: source=certificate")
            return SUCCESS_EXIT_CODE
        if args.csr is not None:
            LOGGER.debug("Fingerprint command: source=csr path=%s", args.csr)
            print(FingerprintCalculator.from_csr(Path(args.csr)))
            LOGGER.debug("Fingerprint command completed: source=csr")
            return SUCCESS_EXIT_CODE
        if args.private_key is not None:
            LOGGER.debug(
                "Fingerprint command: source=private_key path=%s", args.private_key
            )
            print(FingerprintCalculator.from_private_key(Path(args.private_key)))
            LOGGER.debug("Fingerprint command completed: source=private_key")
            return SUCCESS_EXIT_CODE
        account_key_path = resolver.required_path(
            None,
            "acme_account_key_path",
            "ACME_ACCOUNT_KEY_PATH",
            "--acme-account-key requires acme_account_key_path",
        )
        LOGGER.debug(
            "Fingerprint command: source=acme_account_key path=%s", account_key_path
        )
        print(FingerprintCalculator.from_private_key(account_key_path))
        LOGGER.debug("Fingerprint command completed: source=acme_account_key")
        return SUCCESS_EXIT_CODE

    def run_spc_token(
        self, args: argparse.Namespace, resolver: CliValueResolver
    ) -> int:
        """Run the generic STI-PA SPC token workflow."""

        environment = self.resolve_stipa_environment(args, resolver)
        base_url = self.resolve_stipa_base_url(args, resolver, environment)
        LOGGER.debug(
            "SPC token command: environment=%s base_url=%s encoding=%s",
            environment,
            base_url,
            args.encoding,
        )
        tn_auth_list_value = TnAuthList(
            resolver.required_string(
                args.spc, "stipa_spc", "STIPA_SPC", "--spc or STIPA_SPC"
            )
        ).encoded(args.encoding)
        LOGGER.debug(
            "SPC token command: TNAuthList encoded length=%s", len(tn_auth_list_value)
        )
        package = StipaClient(
            StipaSettings(
                base_url=base_url,
                user_id=resolver.required_string(
                    args.user_id,
                    "stipa_user_id",
                    "STIPA_USER_ID",
                    "--user-id or STIPA_USER_ID",
                ),
                password=resolver.required_string(
                    args.password,
                    "stipa_password",
                    "STIPA_PASSWORD",
                    "--password or STIPA_PASSWORD",
                ),
                sp_id=resolver.required_string(
                    args.sp_id, "stipa_sp_id", "STIPA_SP_ID", "--sp-id or STIPA_SP_ID"
                ),
                expected_crl_url=resolver.string(
                    args.expected_crl_url,
                    "stipa_expected_crl_url",
                    "STIPA_EXPECTED_CRL_URL",
                ),
                timeout_seconds=resolver.integer(
                    args.timeout_seconds,
                    "stipa_timeout_seconds",
                    "STIPA_TIMEOUT_SECONDS",
                    DEFAULT_TIMEOUT_SECONDS,
                ),
            )
        ).request_validated_token_package(
            tn_auth_list_value,
            resolver.required_string(
                args.fingerprint,
                "stipa_atc_fingerprint",
                "STIPA_ATC_FINGERPRINT",
                "--fingerprint or STIPA_ATC_FINGERPRINT",
            ),
        )
        output = self.spc_token_output(package, args.include_token)
        output_dir = resolver.path(
            args.output_dir, "stipa_output_dir", "STIPA_OUTPUT_DIR"
        )
        if output_dir is not None:
            LOGGER.debug(
                "SPC token command: writing artifacts output_dir=%s "
                "include_token=%s write_token_artifacts=%s",
                output_dir,
                args.include_token,
                args.write_token_artifacts,
            )
            self.write_spc_token_artifacts(
                output_dir, package, args.include_token, args.write_token_artifacts
            )
        LOGGER.debug(
            "SPC token command completed: crl_url=%s x5u=%s jti=%s exp=%s",
            package.crl_url,
            package.x5u,
            package.jti,
            package.exp,
        )
        print(json.dumps(output, indent=2, sort_keys=True))
        return SUCCESS_EXIT_CODE

    def run_validate_cert(
        self, args: argparse.Namespace, resolver: CliValueResolver
    ) -> int:
        """Run local key/certificate pair validation."""

        key_path = resolver.required_path(
            args.key, "shaken_key_path", "SHAKEN_KEY_PATH", "--key"
        )
        certificate_path = resolver.required_path(
            args.certificate,
            "shaken_certificate_path",
            "SHAKEN_CERTIFICATE_PATH",
            "--certificate",
        )
        LOGGER.debug(
            "Validate cert command: key_path=%s certificate_path=%s",
            key_path,
            certificate_path,
        )
        manager = ShakenCertificateManager()
        LOGGER.debug("Validate cert command: loading private key")
        private_key = manager.load_certificate_key(key_path)
        LOGGER.debug("Validate cert command: parsing certificate")
        certificate = manager.parse_certificate(certificate_path.read_bytes())
        LOGGER.debug("Validate cert command: checking key match")
        manager.require_key_match(certificate, private_key)
        print("key and certificate match")
        LOGGER.debug("Validate cert command completed")
        return SUCCESS_EXIT_CODE

    def run_peeringhub_account_status(
        self, args: argparse.Namespace, resolver: CliValueResolver
    ) -> int:
        """Run Peeringhub ACME account preparation and status verification."""

        environment = self.resolve_peeringhub_environment(args, resolver, required=True)
        acme_base_url = self.resolve_peeringhub_acme_base_url(
            args, resolver, environment
        )
        account_key_path = resolver.required_path(
            args.account_key_path,
            "acme_account_key_path",
            "ACME_ACCOUNT_KEY_PATH",
            "--account-key-path",
        )
        account_state_path = resolver.required_path(
            args.account_state_path,
            "acme_account_state_path",
            "ACME_ACCOUNT_STATE_PATH",
            "--account-state-path",
        )
        acme_kid = resolver.required_string(args.kid, "acme_kid", "ACME_KID", "--kid")
        timeout_seconds = resolver.integer(
            args.timeout_seconds,
            "acme_timeout_seconds",
            "ACME_TIMEOUT_SECONDS",
            DEFAULT_TIMEOUT_SECONDS,
        )
        bad_nonce_retries = resolver.integer(
            args.bad_nonce_retries,
            "acme_bad_nonce_retries",
            "ACME_BAD_NONCE_RETRIES",
            DEFAULT_BAD_NONCE_RETRIES,
        )
        LOGGER.debug(
            "Peeringhub account status command: environment=%s acme_base_url=%s "
            "account_key_path=%s account_state_path=%s timeout_seconds=%s "
            "bad_nonce_retries=%s",
            environment,
            acme_base_url,
            account_key_path,
            account_state_path,
            timeout_seconds,
            bad_nonce_retries,
        )
        state = PeeringhubIssuer.for_account_status(
            environment=environment,
            acme_base_url=acme_base_url,
            account_key_path=account_key_path,
            account_state_path=account_state_path,
            acme_kid=acme_kid,
            timeout_seconds=timeout_seconds,
            bad_nonce_retries=bad_nonce_retries,
        ).prepare_account()
        LOGGER.debug(
            "Peeringhub account status command completed: account_url=%s status=%s",
            state.account_url,
            state.status,
        )
        print(json.dumps(state.__dict__, indent=2, sort_keys=True))
        return SUCCESS_EXIT_CODE

    def run_peeringhub_issue(
        self, args: argparse.Namespace, resolver: CliValueResolver
    ) -> int:
        """Run full Peeringhub STIR/SHAKEN certificate issuance."""

        profile = self.peeringhub_profile_from_args(args, resolver, required=True)
        output_dir = resolver.required_path(
            args.output_dir, "shaken_output_dir", "SHAKEN_OUTPUT_DIR", "--output-dir"
        )
        LOGGER.debug(
            "Peeringhub issue command: environment=%s acme_base_url=%s "
            "stipa_base_url=%s stipa_crl_url=%s output_dir=%s",
            profile.environment,
            profile.acme_base_url,
            profile.stipa_base_url,
            profile.stipa_crl_url,
            output_dir,
        )
        output_dir.mkdir(parents=True, exist_ok=False)
        spc = resolver.required_string(
            args.spc, "stipa_spc", "STIPA_SPC", "--spc or STIPA_SPC"
        )
        tn_auth_list = TnAuthList(spc)
        account_key_path = resolver.required_path(
            args.account_key_path,
            "acme_account_key_path",
            "ACME_ACCOUNT_KEY_PATH",
            "--account-key-path",
        )
        account_state_path = resolver.required_path(
            args.account_state_path,
            "acme_account_state_path",
            "ACME_ACCOUNT_STATE_PATH",
            "--account-state-path",
        )
        acme_kid = resolver.required_string(args.kid, "acme_kid", "ACME_KID", "--kid")
        critical_days = resolver.integer(
            args.critical_days,
            "shaken_critical_days",
            "SHAKEN_CRITICAL_DAYS",
            DEFAULT_CRITICAL_DAYS,
        )
        acme_timeout_seconds = resolver.integer(
            args.timeout_seconds,
            "acme_timeout_seconds",
            "ACME_TIMEOUT_SECONDS",
            DEFAULT_TIMEOUT_SECONDS,
        )
        acme_bad_nonce_retries = resolver.integer(
            args.bad_nonce_retries,
            "acme_bad_nonce_retries",
            "ACME_BAD_NONCE_RETRIES",
            DEFAULT_BAD_NONCE_RETRIES,
        )
        acme_poll_interval_seconds = resolver.integer(
            args.poll_interval_seconds,
            "acme_poll_interval_seconds",
            "ACME_POLL_INTERVAL_SECONDS",
            DEFAULT_POLL_INTERVAL_SECONDS,
        )
        acme_poll_timeout_seconds = resolver.integer(
            args.poll_timeout_seconds,
            "acme_poll_timeout_seconds",
            "ACME_POLL_TIMEOUT_SECONDS",
            DEFAULT_POLL_TIMEOUT_SECONDS,
        )
        LOGGER.debug(
            "Peeringhub issue command: account_key_path=%s account_state_path=%s "
            "critical_days=%s acme_timeout_seconds=%s bad_nonce_retries=%s "
            "poll_interval_seconds=%s poll_timeout_seconds=%s",
            account_key_path,
            account_state_path,
            critical_days,
            acme_timeout_seconds,
            acme_bad_nonce_retries,
            acme_poll_interval_seconds,
            acme_poll_timeout_seconds,
        )
        issuer = PeeringhubIssuer.build(
            profile=profile,
            account_key_path=account_key_path,
            account_state_path=account_state_path,
            acme_kid=acme_kid,
            stipa_settings=self.peeringhub_stipa_settings(args, resolver, profile),
            certificate_policy=ShakenCertificatePolicy(
                subject=self.shaken_subject_from_args(args, resolver),
                tn_auth_list_der=tn_auth_list.der(),
                expected_crl_url=profile.stipa_crl_url,
                critical_days=critical_days,
            ),
            acme_timeout_seconds=acme_timeout_seconds,
            acme_bad_nonce_retries=acme_bad_nonce_retries,
            acme_poll_interval_seconds=acme_poll_interval_seconds,
            acme_poll_timeout_seconds=acme_poll_timeout_seconds,
        )
        LOGGER.debug("Peeringhub issue command: starting issuance workflow")
        result = issuer.issue(
            spc,
            output_dir / "certificate.key",
            resolver.string(args.not_before, "shaken_not_before", "SHAKEN_NOT_BEFORE"),
            resolver.string(args.not_after, "shaken_not_after", "SHAKEN_NOT_AFTER"),
        )
        LOGGER.debug("Peeringhub issue command: writing issuance outputs")
        self.write_issuance_outputs(output_dir, result)
        print(str(output_dir))
        LOGGER.debug(
            "Peeringhub issue command completed: order_url=%s certificate_url=%s",
            result.order_url,
            result.certificate_url,
        )
        return SUCCESS_EXIT_CODE

    def run_csr(self, args: argparse.Namespace, resolver: CliValueResolver) -> int:
        """Run local SHAKEN key and CSR generation."""

        crl_url = (
            resolver.string(args.crl_url, "shaken_crl_url", "SHAKEN_CRL_URL") or ""
        )
        include_crl_distribution_points = (
            not args.omit_crl_distribution_points and crl_url != ""
        )
        key_out = resolver.required_path(
            args.key_out,
            "shaken_key_out",
            "SHAKEN_KEY_OUT",
            "--key-out",
            DEFAULT_SHAKEN_KEY_OUT,
        )
        csr_pem_out = resolver.required_path(
            args.csr_pem_out,
            "shaken_csr_pem_out",
            "SHAKEN_CSR_PEM_OUT",
            "--csr-pem-out",
            DEFAULT_SHAKEN_CSR_PEM_OUT,
        )
        csr_der_out = resolver.path(
            args.csr_der_out, "shaken_csr_der_out", "SHAKEN_CSR_DER_OUT"
        )
        LOGGER.debug(
            "CSR command: key_out=%s csr_pem_out=%s csr_der_out=%s "
            "include_crl_distribution_points=%s crl_url_configured=%s",
            key_out,
            csr_pem_out,
            csr_der_out,
            include_crl_distribution_points,
            crl_url != "",
        )
        tn_auth_list = TnAuthList(
            resolver.required_string(
                args.spc, "stipa_spc", "STIPA_SPC", "--spc or STIPA_SPC"
            )
        )
        policy = ShakenCertificatePolicy(
            subject=self.shaken_subject_from_args(args, resolver),
            tn_auth_list_der=tn_auth_list.der(),
            expected_crl_url=crl_url,
            critical_days=DEFAULT_CRITICAL_DAYS,
            include_crl_distribution_points=include_crl_distribution_points,
        )
        manager = ShakenCertificateManager(policy)
        LOGGER.debug("CSR command: generating private key")
        private_key = manager.generate_certificate_key(key_out)
        LOGGER.debug("CSR command: building CSR")
        csr = manager.build_csr(private_key)
        self.write_bytes(csr_pem_out, manager.csr_pem(csr), 0o600)
        if csr_der_out is not None:
            self.write_bytes(csr_der_out, manager.csr_der(csr), 0o600)
        LOGGER.debug("CSR command completed")
        return SUCCESS_EXIT_CODE

    def parse_args(self, argv: list[str] | None) -> argparse.Namespace:
        """Parse CLI arguments.

        :param argv: Optional argument vector.
        :type argv: list[str] | None
        :return: Parsed namespace.
        :rtype: argparse.Namespace
        """

        parser = argparse.ArgumentParser(
            description="STIR/SHAKEN toolkit",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=dedent(
                """\
                Values resolve in this order: CLI args, --config YAML,
                prefixed environment variables, then built-in defaults.
                """
            ),
        )
        parser.add_argument("--debug", action="store_true", help="Enable debug logging")
        self.add_file_argument(
            parser,
            "--config",
            help="Optional toolkit YAML config path",
            extensions=YAML_EXTENSIONS,
        )
        subparsers = parser.add_subparsers(dest="command", required=True)
        self.add_tnauth_parser(subparsers)
        self.add_fingerprint_parser(subparsers)
        self.add_spc_token_parser(subparsers)
        self.add_validate_cert_parser(subparsers)
        self.add_peeringhub_account_parser(subparsers)
        self.add_peeringhub_issue_parser(subparsers)
        self.add_csr_parser(subparsers)
        argcomplete.autocomplete(parser)
        return parser.parse_args(argv)

    def add_tnauth_parser(self, subparsers: Any) -> None:
        """Add the TNAuthList parser."""

        parser = subparsers.add_parser(
            "tnauth",
            help="Encode a TNAuthList value",
            description=dedent(
                """\
                Encode a local TNAuthList value from an SPC. This command is
                local-only and does not contact STI-PA or ACME.
                """
            ),
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        parser.add_argument("--spc", help="Service provider code")
        parser.add_argument(
            "--encoding",
            choices=["base64", "base64url"],
            default="base64",
            help="Output encoding, default: %(default)s",
        )

    def add_fingerprint_parser(self, subparsers: Any) -> None:
        """Add the fingerprint parser."""

        parser = subparsers.add_parser(
            "fingerprint",
            help="Calculate an STI-PA SHA256 fingerprint",
            description=dedent(
                """\
                Calculate a local STI-PA-formatted SHA256 fingerprint from a
                certificate, CSR, private key, or configured ACME account key.
                This command is local-only.
                """
            ),
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        self.add_file_argument(
            parser,
            "--certificate",
            help="PEM certificate path",
            extensions=CERTIFICATE_EXTENSIONS,
        )
        self.add_file_argument(
            parser, "--csr", help="PEM CSR path", extensions=CSR_EXTENSIONS
        )
        self.add_file_argument(
            parser,
            "--private-key",
            help="PEM private key path",
            extensions=KEY_EXTENSIONS,
        )
        parser.add_argument(
            "--acme-account-key",
            action="store_true",
            help="Fingerprint the configured ACME account key",
        )

    def add_spc_token_parser(self, subparsers: Any) -> None:
        """Add the generic SPC token parser."""

        parser = subparsers.add_parser(
            "spc-token",
            help="Request and validate a generic STI-PA SPC token",
            description=dedent(
                """\
                Request and validate an SPC token directly from STI-PA. This is
                provider-neutral token tooling; Peeringhub issuance obtains and
                submits its SPC token internally.
                """
            ),
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        parser.add_argument("--user-id", help="STI-PA API user ID")
        parser.add_argument("--password", help="STI-PA API password")
        parser.add_argument("--sp-id", help="STI-PA service provider ID")
        parser.add_argument("--spc", help="Service provider code")
        parser.add_argument("--fingerprint", help="ATC fingerprint")
        parser.add_argument(
            "--staging", action="store_true", help="Use the STI-PA staging URL"
        )
        parser.add_argument("--base-url", help="Override STI-PA base URL")
        parser.add_argument("--expected-crl-url", help="Optional expected CRL URL")
        self.add_directory_argument(
            parser, "--output-dir", help="Optional artifact output directory"
        )
        parser.add_argument(
            "--encoding",
            choices=["base64", "base64url"],
            default="base64",
            help="TNAuthList encoding, default: %(default)s",
        )
        parser.add_argument(
            "--timeout-seconds",
            type=int,
            help="STI-PA HTTP timeout seconds",
        )
        parser.add_argument(
            "--include-token", action="store_true", help="Include JWT token in output"
        )
        parser.add_argument(
            "--write-token-artifacts",
            action="store_true",
            help="Write sensitive token diagnostics when --output-dir is set",
        )

    def add_validate_cert_parser(self, subparsers: Any) -> None:
        """Add the certificate validation parser."""

        parser = subparsers.add_parser(
            "validate-cert",
            help="Validate a key/certificate pair",
            description=dedent(
                """\
                Validate that a local SHAKEN certificate public key matches a
                local EC P-256 private key. This command is local-only.
                """
            ),
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        self.add_file_argument(
            parser, "--key", help="Private key path", extensions=KEY_EXTENSIONS
        )
        self.add_file_argument(
            parser,
            "--certificate",
            help="Certificate path",
            extensions=CERTIFICATE_EXTENSIONS,
        )

    def add_peeringhub_account_parser(self, subparsers: Any) -> None:
        """Add the Peeringhub account parser."""

        parser = subparsers.add_parser(
            "peeringhub-account-status",
            help="Create or verify a Peeringhub ACME account",
            description=dedent(
                """\
                Prepare or verify the configured Peeringhub ACME account. This
                command contacts Peeringhub ACME but does not request a cert.
                """
            ),
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        self.add_peeringhub_environment_args(parser, include_stipa_urls=False)
        self.add_acme_account_args(parser)

    def add_peeringhub_issue_parser(self, subparsers: Any) -> None:
        """Add the Peeringhub issuance parser."""

        parser = subparsers.add_parser(
            "peeringhub-issue",
            help="Issue a Peeringhub STIR/SHAKEN certificate",
            description=dedent(
                """\
                Run the full Peeringhub ACME issuance workflow. This command
                contacts Peeringhub ACME and STI-PA, creates an SPC token
                internally, submits the challenge, and downloads the certificate.
                """
            ),
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        self.add_peeringhub_environment_args(parser, include_stipa_urls=True)
        self.add_stipa_args(parser)
        self.add_acme_account_args(parser)
        self.add_subject_args(parser)
        parser.add_argument("--spc", help="Service provider code")
        self.add_directory_argument(parser, "--output-dir", help="Output directory")
        parser.add_argument("--not-before", help="Optional RFC 3339 notBefore")
        parser.add_argument("--not-after", help="Optional RFC 3339 notAfter")
        parser.add_argument(
            "--poll-interval-seconds", type=int, help="ACME poll interval seconds"
        )
        parser.add_argument(
            "--poll-timeout-seconds", type=int, help="ACME poll timeout seconds"
        )
        parser.add_argument("--critical-days", type=int, help="Critical threshold days")

    def add_csr_parser(self, subparsers: Any) -> None:
        """Add the CSR parser."""

        parser = subparsers.add_parser(
            "csr",
            help="Generate a SHAKEN key and CSR",
            description=dedent(
                """\
                Generate a local EC P-256 SHAKEN private key and CSR with a
                TNAuthList extension. This command is local-only.
                """
            ),
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        self.add_subject_args(parser)
        parser.add_argument("--spc", help="Service provider code")
        parser.add_argument("--crl-url", help="Expected CRL URL")
        self.add_file_argument(
            parser,
            "--key-out",
            help=f"Private key output, default: {DEFAULT_SHAKEN_KEY_OUT}",
            extensions=KEY_EXTENSIONS,
        )
        self.add_file_argument(
            parser,
            "--csr-pem-out",
            help=f"CSR PEM output, default: {DEFAULT_SHAKEN_CSR_PEM_OUT}",
            extensions=CSR_EXTENSIONS,
        )
        self.add_file_argument(
            parser,
            "--csr-der-out",
            help="Optional CSR DER output",
            extensions=(".der",),
        )
        parser.add_argument(
            "--omit-crl-distribution-points",
            action="store_true",
            help="Omit CRL Distribution Points from CSR",
        )

    def add_peeringhub_environment_args(
        self, parser: argparse.ArgumentParser, include_stipa_urls: bool
    ) -> None:
        """Add Peeringhub environment arguments to a parser."""

        parser.add_argument(
            "--environment",
            choices=["staging", "production"],
            help="Peeringhub environment",
        )
        parser.add_argument("--acme-base-url", help="Override Peeringhub ACME URL")
        if include_stipa_urls:
            parser.add_argument(
                "--stipa-base-url", help="Override Peeringhub STI-PA URL"
            )
            parser.add_argument("--stipa-crl-url", help="Override Peeringhub CRL URL")

    def add_stipa_args(self, parser: argparse.ArgumentParser) -> None:
        """Add STI-PA credential arguments to a parser."""

        parser.add_argument("--stipa-user-id", help="STI-PA user ID")
        parser.add_argument("--stipa-password", help="STI-PA password")
        parser.add_argument("--sp-id", help="STI-PA service provider ID")
        parser.add_argument("--stipa-timeout-seconds", type=int, help="STI-PA timeout")

    def add_acme_account_args(self, parser: argparse.ArgumentParser) -> None:
        """Add ACME account arguments to a parser."""

        self.add_file_argument(
            parser,
            "--account-key-path",
            help="ACME account key path",
            extensions=KEY_EXTENSIONS,
        )
        self.add_file_argument(
            parser,
            "--account-state-path",
            help="ACME account state path",
            extensions=JSON_EXTENSIONS,
        )
        parser.add_argument("--kid", help="Local ACME key ID")
        parser.add_argument("--timeout-seconds", type=int, help="HTTP timeout seconds")
        parser.add_argument("--bad-nonce-retries", type=int, help="badNonce retries")

    def add_file_argument(
        self,
        parser: argparse.ArgumentParser,
        *flags: str,
        help: str,
        extensions: tuple[str, ...],
    ) -> argparse.Action:
        """Add a file path argument with shell completion metadata."""

        action = parser.add_argument(*flags, help=help)
        setattr(action, "completer", FilesCompleter(allowednames=extensions))
        return action

    def add_directory_argument(
        self, parser: argparse.ArgumentParser, *flags: str, help: str
    ) -> argparse.Action:
        """Add a directory path argument with shell completion metadata."""

        action = parser.add_argument(*flags, help=help)
        setattr(action, "completer", DirectoriesCompleter())
        return action

    def add_subject_args(self, parser: argparse.ArgumentParser) -> None:
        """Add X.509 subject arguments to a parser."""

        parser.add_argument("--country", help="Subject country")
        parser.add_argument("--state", help="Subject state")
        parser.add_argument("--locality", help="Subject locality")
        parser.add_argument("--organization", help="Subject organization")
        parser.add_argument("--common-name", help="Subject common name")
        parser.add_argument("--organizational-unit", help="Subject organizational unit")

    def peeringhub_profile_from_args(
        self,
        args: argparse.Namespace,
        resolver: CliValueResolver,
        required: bool,
    ) -> PeeringhubProfile:
        """Build a Peeringhub profile from resolved values."""

        environment = self.resolve_peeringhub_environment(args, resolver, required)
        defaults = PeeringhubProfile.for_environment(environment)
        return PeeringhubProfile(
            environment=environment,
            acme_base_url=self.resolve_peeringhub_acme_base_url(
                args, resolver, environment
            ),
            stipa_base_url=resolver.string(
                getattr(args, "stipa_base_url", None),
                "peeringhub_stipa_base_url",
                "PEERINGHUB_STIPA_BASE_URL",
                resolver.mapped_url(
                    "stipa_base_url", environment, defaults.stipa_base_url
                ),
            )
            or defaults.stipa_base_url,
            stipa_crl_url=resolver.string(
                getattr(args, "stipa_crl_url", None),
                "peeringhub_stipa_crl_url",
                "PEERINGHUB_STIPA_CRL_URL",
                resolver.mapped_url(
                    "stipa_crl_url", environment, defaults.stipa_crl_url
                ),
            )
            or defaults.stipa_crl_url,
            tn_auth_list_encoding="base64",
        )

    def resolve_peeringhub_environment(
        self, args: argparse.Namespace, resolver: CliValueResolver, required: bool
    ) -> str:
        """Resolve the Peeringhub environment for provider-specific commands."""

        environment = resolver.string(
            getattr(args, "environment", None),
            "peeringhub_environment",
            "PEERINGHUB_ENVIRONMENT",
        )
        if environment is None:
            environment = resolver.string(
                None, "stipa_environment", "STIPA_ENVIRONMENT"
            )
        if environment is None and required:
            raise StirShakenError(
                "Missing required value: --environment or PEERINGHUB_ENVIRONMENT"
            )
        environment = environment or DEFAULT_STIPA_ENVIRONMENT
        if environment not in {"staging", "production"}:
            raise StirShakenError("environment must be staging or production")
        return environment

    def resolve_peeringhub_acme_base_url(
        self,
        args: argparse.Namespace,
        resolver: CliValueResolver,
        environment: str,
    ) -> str:
        """Resolve the Peeringhub ACME base URL."""

        defaults = PeeringhubProfile.for_environment(environment)
        return (
            resolver.string(
                getattr(args, "acme_base_url", None),
                "peeringhub_acme_base_url",
                "PEERINGHUB_ACME_BASE_URL",
                resolver.mapped_url(
                    "acme_base_url", environment, defaults.acme_base_url
                ),
            )
            or defaults.acme_base_url
        )

    def peeringhub_stipa_settings(
        self,
        args: argparse.Namespace,
        resolver: CliValueResolver,
        profile: PeeringhubProfile,
    ) -> StipaSettings:
        """Build Peeringhub STI-PA settings from resolved values."""

        minimum_lifetime = resolver.integer(
            args.poll_timeout_seconds,
            "acme_poll_timeout_seconds",
            "ACME_POLL_TIMEOUT_SECONDS",
            DEFAULT_POLL_TIMEOUT_SECONDS,
        )
        return StipaSettings(
            base_url=profile.stipa_base_url,
            user_id=resolver.required_string(
                args.stipa_user_id,
                "stipa_user_id",
                "STIPA_USER_ID",
                "--stipa-user-id or STIPA_USER_ID",
            ),
            password=resolver.required_string(
                args.stipa_password,
                "stipa_password",
                "STIPA_PASSWORD",
                "--stipa-password or STIPA_PASSWORD",
            ),
            sp_id=resolver.required_string(
                args.sp_id, "stipa_sp_id", "STIPA_SP_ID", "--sp-id or STIPA_SP_ID"
            ),
            expected_crl_url=profile.stipa_crl_url,
            timeout_seconds=resolver.integer(
                args.stipa_timeout_seconds,
                "stipa_timeout_seconds",
                "STIPA_TIMEOUT_SECONDS",
                DEFAULT_TIMEOUT_SECONDS,
            ),
            minimum_token_lifetime_seconds=minimum_lifetime,
        )

    def shaken_subject_from_args(
        self, args: argparse.Namespace, resolver: CliValueResolver
    ) -> ShakenSubject:
        """Build a SHAKEN subject from resolved values."""

        return ShakenSubject(
            country=resolver.required_string(
                args.country,
                "shaken_subject_country",
                "SHAKEN_SUBJECT_COUNTRY",
                "--country",
                "US",
            ),
            state=resolver.required_string(
                args.state, "shaken_subject_state", "SHAKEN_SUBJECT_STATE", "--state"
            ),
            locality=resolver.required_string(
                args.locality,
                "shaken_subject_locality",
                "SHAKEN_SUBJECT_LOCALITY",
                "--locality",
            ),
            organization=resolver.required_string(
                args.organization,
                "shaken_subject_organization",
                "SHAKEN_SUBJECT_ORGANIZATION",
                "--organization",
            ),
            organizational_unit=resolver.string(
                args.organizational_unit,
                "shaken_subject_organizational_unit",
                "SHAKEN_SUBJECT_ORGANIZATIONAL_UNIT",
                "",
            )
            or "",
            common_name=resolver.required_string(
                args.common_name,
                "shaken_subject_common_name",
                "SHAKEN_SUBJECT_COMMON_NAME",
                "--common-name",
            ),
        )

    def resolve_stipa_environment(
        self, args: argparse.Namespace, resolver: CliValueResolver
    ) -> str:
        """Resolve a generic STI-PA environment."""

        environment = resolver.string(
            None,
            "stipa_environment",
            "STIPA_ENVIRONMENT",
            DEFAULT_STIPA_ENVIRONMENT,
        )
        if getattr(args, "staging", False):
            environment = "staging"
        if environment not in {"staging", "production"}:
            raise StirShakenError("STI-PA environment must be staging or production")
        return environment

    def resolve_stipa_base_url(
        self,
        args: argparse.Namespace,
        resolver: CliValueResolver,
        environment: str,
    ) -> str:
        """Resolve a generic STI-PA base URL."""

        if getattr(args, "base_url", None):
            return str(args.base_url)
        configured_base_url = resolver.config.get("stipa_base_url")
        if isinstance(configured_base_url, dict):
            environment_url = configured_base_url.get(environment)
            if not resolver.is_blank(environment_url):
                return str(environment_url)
        if not resolver.is_blank(configured_base_url):
            return str(configured_base_url)
        return (
            resolver.string(
                None,
                "unused_stipa_base_url",
                "STIPA_BASE_URL",
                PEERINGHUB_STIPA_URLS[environment],
            )
            or PEERINGHUB_STIPA_URLS[environment]
        )

    def spc_token_output(
        self, package: StipaTokenPackage, include_token: bool
    ) -> dict[str, object]:
        """Build sanitized SPC token CLI output."""

        output: dict[str, object] = {
            "crl_url": package.crl_url,
            "exp": package.exp,
            "fingerprint": package.fingerprint,
            "jti": package.jti,
            "tn_auth_list_value": package.tn_auth_list_value,
            "x5u": package.x5u,
        }
        if include_token:
            output["token"] = package.token
        return output

    def write_spc_token_artifacts(
        self,
        output_dir: Path,
        package: StipaTokenPackage,
        include_token: bool,
        write_token_artifacts: bool,
    ) -> None:
        """Write optional SPC token artifacts."""

        output_dir.mkdir(parents=True, exist_ok=True)
        LOGGER.debug("Writing SPC token summary artifact: %s", output_dir)
        self.write_json(
            output_dir / "spc-token-summary.json",
            self.spc_token_output(package, False),
            0o600,
        )
        if not write_token_artifacts:
            LOGGER.debug("Sensitive SPC token artifacts disabled")
            return
        LOGGER.debug("Writing sensitive SPC token diagnostic artifacts: %s", output_dir)
        self.write_json(
            output_dir / "spc-token-request.json", package.request_body, 0o600
        )
        self.write_json(
            output_dir / "spc-token-response.json", package.response_body, 0o600
        )
        self.write_json(output_dir / "spc-token-header.json", package.header, 0o600)
        self.write_json(output_dir / "spc-token-payload.json", package.payload, 0o600)
        self.write_text(
            output_dir / "spc-token-signing-cert.crt",
            package.signing_certificate_pem,
            0o600,
        )
        self.write_bytes(
            output_dir / "spc-token-public-key.pem", package.public_key_pem, 0o600
        )
        self.write_bytes(output_dir / "stipa.crl", package.crl_bytes, 0o600)
        self.write_text(output_dir / "ca-handoff.txt", self.ca_handoff(package), 0o600)
        if include_token:
            self.write_text(output_dir / "spc-token.jwt", f"{package.token}\n", 0o600)

    def ca_handoff(self, package: StipaTokenPackage) -> str:
        """Build a CA handoff text artifact."""

        return (
            "STI-CA SHAKEN Certificate Request Handoff\n"
            "========================================\n\n"
            f"TNAuthList tkvalue: {package.tn_auth_list_value}\n"
            f"ATC fingerprint: {package.fingerprint}\n"
            f"STI-PA x5u: {package.x5u}\n"
            f"CRL URL: {package.crl_url}\n\n"
            "SPC Token JWT\n"
            "-------------\n"
            f"{package.token}\n\n"
            "Verified SPC Token Payload\n"
            "--------------------------\n"
            f"{json.dumps(package.payload, indent=2, sort_keys=True)}\n"
        )

    def write_issuance_outputs(
        self, output_dir: Path, result: StirShakenIssuanceResult
    ) -> None:
        """Write Peeringhub issuance output files."""

        LOGGER.debug("Writing issuance output: %s", output_dir / "csr.pem")
        self.write_bytes(output_dir / "csr.pem", result.csr_pem, 0o600)
        LOGGER.debug("Writing issuance output: %s", output_dir / "csr.der")
        self.write_bytes(output_dir / "csr.der", result.csr_der, 0o600)
        LOGGER.debug("Writing issuance output: %s", output_dir / "leaf.pem")
        self.write_text(output_dir / "leaf.pem", result.leaf_pem, 0o600)
        LOGGER.debug(
            "Writing issuance output: %s", output_dir / "certificate-chain.pem"
        )
        self.write_text(output_dir / "certificate-chain.pem", result.chain_pem, 0o600)
        LOGGER.debug("Writing issuance output: %s", output_dir / "issuance.json")
        self.write_json(
            output_dir / "issuance.json",
            {
                "account": result.account_state.__dict__,
                "authorization_url": result.authorization_url,
                "certificate_details": result.certificate_details.as_dict(),
                "certificate_url": result.certificate_url,
                "finalize_url": result.finalize_url,
                "order_url": result.order_url,
                "stipa_token_exp": result.stipa_token.exp,
                "stipa_token_jti": result.stipa_token.jti,
                "tn_auth_list_value": result.tn_auth_list_value,
            },
            0o600,
        )

    def write_bytes(self, path: Path, content: bytes, mode: int) -> None:
        """Write bytes with an explicit mode."""

        path.write_bytes(content)
        os.chmod(path, mode)

    def write_text(self, path: Path, content: str, mode: int) -> None:
        """Write text with an explicit mode."""

        path.write_text(content)
        os.chmod(path, mode)

    def write_json(self, path: Path, content: dict[str, object], mode: int) -> None:
        """Write JSON with an explicit mode."""

        self.write_text(
            path, json.dumps(content, indent=2, sort_keys=True) + "\n", mode
        )


def main() -> int:
    """Run the CLI entry point.

    :return: Process exit code.
    :rtype: int
    """

    return StirShakenToolkitCli().run()


if __name__ == "__main__":
    sys.exit(main())
