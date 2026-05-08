"""Command-line interface for STIR/SHAKEN toolkit operations."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
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
    IssuanceValidationError,
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
    PeeringhubAccountPaths,
    PeeringhubIssuer,
    PeeringhubProfile,
)

SUCCESS_EXIT_CODE = 0
FAILURE_EXIT_CODE = 1
DEFAULT_TIMEOUT_SECONDS = 30
DEFAULT_MINIMUM_CERTIFICATE_LIFETIME_DAYS = 21
DEFAULT_POLL_INTERVAL_SECONDS = 5
DEFAULT_POLL_TIMEOUT_SECONDS = 180
DEFAULT_BAD_NONCE_RETRIES = 2
DEFAULT_STIPA_ENVIRONMENT = "production"
DEFAULT_SHAKEN_KEY_OUT = "shaken.key"
DEFAULT_SHAKEN_CSR_PEM_OUT = "shaken.csr"
DEFAULT_ISSUANCE_OUTPUT_DIR_PREFIX = "shaken-cert"
LOGGER = logging.getLogger(__name__)
CERTIFICATE_EXTENSIONS = (".crt", ".pem")
CSR_EXTENSIONS = (".csr", ".pem")
KEY_EXTENSIONS = (".key", ".pem")
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

        if args.command == "fingerprint":
            return self.run_fingerprint(args, resolver)
        if args.command == "spc-token":
            return self.run_spc_token(args, resolver)
        if args.command == "validate-cert":
            return self.run_validate_cert(args, resolver)
        if args.command == "peeringhub-account-setup":
            return self.run_peeringhub_account_setup(args, resolver)
        if args.command == "peeringhub-issue":
            return self.run_peeringhub_issue(args, resolver)
        if args.command == "csr":
            return self.run_csr(args, resolver)
        raise StirShakenError(f"Unsupported command: {args.command}")

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
                + "or --acme-account-key"
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
        environment = self.resolve_peeringhub_environment(
            args, resolver, required=False
        )
        account_paths = self.peeringhub_account_paths(args, resolver, environment)
        LOGGER.debug(
            "Fingerprint command: source=acme_account_key path=%s",
            account_paths.account_key_path,
        )
        print(FingerprintCalculator.from_private_key(account_paths.account_key_path))
        LOGGER.debug("Fingerprint command completed: source=acme_account_key")
        return SUCCESS_EXIT_CODE

    def run_spc_token(
        self, args: argparse.Namespace, resolver: CliValueResolver
    ) -> int:
        """Run the generic STI-PA SPC token workflow."""

        environment = self.resolve_stipa_environment(args, resolver)
        base_url = self.resolve_stipa_base_url(environment)
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
                timeout_seconds=DEFAULT_TIMEOUT_SECONDS,
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
        output = self.spc_token_output(package)
        output_dir = resolver.path(
            args.output_dir, "stipa_output_dir", "STIPA_OUTPUT_DIR"
        )
        if output_dir is not None:
            LOGGER.debug(
                "SPC token command: writing artifacts output_dir=%s "
                + "write_token_artifacts=%s",
                output_dir,
                args.write_token_artifacts,
            )
            self.write_spc_token_artifacts(
                output_dir, package, args.write_token_artifacts
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

    def run_peeringhub_account_setup(
        self, args: argparse.Namespace, resolver: CliValueResolver
    ) -> int:
        """Run Peeringhub ACME account preparation and status verification."""

        environment = self.resolve_peeringhub_environment(
            args, resolver, required=False
        )
        acme_base_url = PeeringhubProfile.for_environment(environment).acme_base_url
        account_paths = self.peeringhub_account_paths(args, resolver, environment)
        acme_kid = resolver.required_string(args.kid, "acme_kid", "ACME_KID", "--kid")
        LOGGER.debug(
            "Peeringhub account setup command: environment=%s acme_base_url=%s "
            + "account_dir=%s account_key_path=%s account_state_path=%s "
            + "timeout_seconds=%s bad_nonce_retries=%s",
            environment,
            acme_base_url,
            account_paths.account_dir,
            account_paths.account_key_path,
            account_paths.account_state_path,
            DEFAULT_TIMEOUT_SECONDS,
            DEFAULT_BAD_NONCE_RETRIES,
        )
        state = PeeringhubIssuer.for_account_status(
            environment=environment,
            acme_base_url=acme_base_url,
            account_key_path=account_paths.account_key_path,
            account_state_path=account_paths.account_state_path,
            acme_kid=acme_kid,
            timeout_seconds=DEFAULT_TIMEOUT_SECONDS,
            bad_nonce_retries=DEFAULT_BAD_NONCE_RETRIES,
        ).prepare_account()
        LOGGER.debug(
            "Peeringhub account setup command completed: account_url=%s status=%s",
            state.account_url,
            state.status,
        )
        print(json.dumps(state.__dict__, indent=2, sort_keys=True))
        return SUCCESS_EXIT_CODE

    def issue_output_dir_from_args(
        self, args: argparse.Namespace, resolver: CliValueResolver
    ) -> Path:
        """Resolve the Peeringhub issuance output directory.

        :param args: Parsed CLI arguments.
        :type args: argparse.Namespace
        :param resolver: CLI value resolver.
        :type resolver: CliValueResolver
        :return: Output directory path.
        :rtype: Path
        """

        output_dir = resolver.path(
            args.output_dir, "shaken_output_dir", "SHAKEN_OUTPUT_DIR"
        )
        if output_dir is not None:
            return output_dir
        return self.default_issue_output_dir()

    def issue_output_dir_source(
        self, args: argparse.Namespace, resolver: CliValueResolver
    ) -> str | None:
        """Return which external source supplied the issuance output directory."""

        if not resolver.is_blank(args.output_dir):
            return "--output-dir"
        if "shaken_output_dir" in resolver.config and not resolver.is_blank(
            resolver.config["shaken_output_dir"]
        ):
            return "shaken_output_dir"
        if "SHAKEN_OUTPUT_DIR" in os.environ and os.environ["SHAKEN_OUTPUT_DIR"] != "":
            return "SHAKEN_OUTPUT_DIR"
        return None

    def default_issue_output_dir(self) -> Path:
        """Return a non-existing default issuance output directory in cwd."""

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        base_path = Path(f"{DEFAULT_ISSUANCE_OUTPUT_DIR_PREFIX}-{timestamp}")
        if not base_path.exists():
            return base_path
        suffix = 1
        while True:
            candidate = Path(f"{base_path}-{suffix}")
            if not candidate.exists():
                return candidate
            suffix += 1

    def run_peeringhub_issue(
        self, args: argparse.Namespace, resolver: CliValueResolver
    ) -> int:
        """Run full Peeringhub STIR/SHAKEN certificate issuance."""

        profile = self.peeringhub_profile_from_args(args, resolver, required=False)
        output_dir = self.issue_output_dir_from_args(args, resolver)
        output_dir_source = self.issue_output_dir_source(args, resolver)
        output_dir_source_label = (
            "configured" if output_dir_source is not None else "generated default"
        )
        LOGGER.debug(
            "Peeringhub issue command: environment=%s acme_base_url=%s "
            + "stipa_base_url=%s stipa_crl_url=%s output_dir=%s "
            + "output_dir_source=%s",
            profile.environment,
            profile.acme_base_url,
            profile.stipa_base_url,
            profile.stipa_crl_url,
            output_dir,
            output_dir_source_label,
        )
        output_dir.mkdir(parents=True, exist_ok=False)
        spc = resolver.required_string(
            args.spc, "stipa_spc", "STIPA_SPC", "--spc or STIPA_SPC"
        )
        default_common_name = (
            f"SHAKEN {spc} {datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
        )
        tn_auth_list = TnAuthList(spc)
        account_paths = self.peeringhub_account_paths(
            args, resolver, profile.environment
        )
        acme_kid = resolver.required_string(args.kid, "acme_kid", "ACME_KID", "--kid")
        LOGGER.debug(
            "Peeringhub issue command: account_dir=%s account_key_path=%s "
            + "account_state_path=%s minimum_certificate_lifetime_days=%s "
            + "acme_timeout_seconds=%s bad_nonce_retries=%s "
            + "poll_interval_seconds=%s poll_timeout_seconds=%s",
            account_paths.account_dir,
            account_paths.account_key_path,
            account_paths.account_state_path,
            DEFAULT_MINIMUM_CERTIFICATE_LIFETIME_DAYS,
            DEFAULT_TIMEOUT_SECONDS,
            DEFAULT_BAD_NONCE_RETRIES,
            DEFAULT_POLL_INTERVAL_SECONDS,
            DEFAULT_POLL_TIMEOUT_SECONDS,
        )
        issuer = PeeringhubIssuer.build(
            profile=profile,
            account_key_path=account_paths.account_key_path,
            account_state_path=account_paths.account_state_path,
            acme_kid=acme_kid,
            stipa_settings=self.peeringhub_stipa_settings(args, resolver, profile),
            certificate_policy=ShakenCertificatePolicy(
                subject=self.shaken_subject_from_args(
                    args, resolver, default_common_name
                ),
                tn_auth_list_der=tn_auth_list.der(),
                expected_crl_url=profile.stipa_crl_url,
                minimum_certificate_lifetime_days=(
                    DEFAULT_MINIMUM_CERTIFICATE_LIFETIME_DAYS
                ),
                include_crl_distribution_points=False,
            ),
            acme_timeout_seconds=DEFAULT_TIMEOUT_SECONDS,
            acme_bad_nonce_retries=DEFAULT_BAD_NONCE_RETRIES,
            acme_poll_interval_seconds=DEFAULT_POLL_INTERVAL_SECONDS,
            acme_poll_timeout_seconds=DEFAULT_POLL_TIMEOUT_SECONDS,
        )
        LOGGER.debug("Peeringhub issue command: starting issuance workflow")
        try:
            result = issuer.issue(
                spc,
                not_before=resolver.string(
                    args.not_before, "shaken_not_before", "SHAKEN_NOT_BEFORE"
                ),
                not_after=resolver.string(
                    args.not_after, "shaken_not_after", "SHAKEN_NOT_AFTER"
                ),
            )
        except IssuanceValidationError as exc:
            LOGGER.debug(
                "Peeringhub issue command: writing validation failure artifacts"
            )
            self.write_issuance_outputs(output_dir, exc.partial_result)
            raise
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
            "CSR command: key_out=%s csr_pem_out=%s csr_der_out=%s",
            key_out,
            csr_pem_out,
            csr_der_out,
        )
        tn_auth_list = TnAuthList(
            resolver.required_string(
                args.spc, "stipa_spc", "STIPA_SPC", "--spc or STIPA_SPC"
            )
        )
        policy = ShakenCertificatePolicy(
            subject=self.shaken_subject_from_args(args, resolver),
            tn_auth_list_der=tn_auth_list.der(),
            expected_crl_url="",
            minimum_certificate_lifetime_days=(
                DEFAULT_MINIMUM_CERTIFICATE_LIFETIME_DAYS
            ),
            include_crl_distribution_points=False,
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
            description=dedent("""\
                STIR/SHAKEN toolkit for local CSR/fingerprint utilities,
                STI-PA SPC token requests, and Peeringhub ACME issuance.
                """),
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=dedent("""\
                Values resolve in this order: CLI args, --config YAML,
                prefixed environment variables, then built-in defaults.
                Subcommand options shown as optional may still be required
                unless supplied by config or environment.
                """),
        )
        parser.add_argument(
            "--debug",
            action="store_true",
            help="Enable debug logging with secrets redacted",
        )
        self.add_file_argument(
            parser,
            "--config",
            help="YAML config file; explicit CLI args take priority",
            extensions=YAML_EXTENSIONS,
        )
        subparsers = parser.add_subparsers(
            dest="command", required=True, metavar="command"
        )
        self.add_fingerprint_parser(subparsers)
        self.add_spc_token_parser(subparsers)
        self.add_validate_cert_parser(subparsers)
        self.add_peeringhub_account_parser(subparsers)
        self.add_peeringhub_issue_parser(subparsers)
        self.add_csr_parser(subparsers)
        argcomplete.autocomplete(parser)
        return parser.parse_args(argv)

    def add_fingerprint_parser(self, subparsers: Any) -> None:
        """Add the fingerprint parser."""

        parser = subparsers.add_parser(
            "fingerprint",
            help="Calculate an STI-PA SHA256 fingerprint",
            description=dedent("""\
                Calculate a local STI-PA-formatted SHA256 fingerprint from a
                certificate, CSR, private key, or configured ACME account key.
                The output is suitable for STI-PA ATC/SPC token requests.
                This command is local-only.
                """),
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        self.add_file_argument(
            parser,
            "--certificate",
            help="Certificate file to fingerprint, PEM or CRT",
            extensions=CERTIFICATE_EXTENSIONS,
        )
        self.add_file_argument(
            parser,
            "--csr",
            help="CSR file to fingerprint, usually shaken.csr",
            extensions=CSR_EXTENSIONS,
        )
        self.add_file_argument(
            parser,
            "--private-key",
            help="Private key whose public key should be fingerprinted",
            extensions=KEY_EXTENSIONS,
        )
        parser.add_argument(
            "--acme-account-key",
            action="store_true",
            help=(
                "Fingerprint the account.key in acme_account_dir / "
                "ACME_ACCOUNT_DIR or the platform default Peeringhub account "
                "directory"
            ),
        )
        self.add_peeringhub_account_dir_arg(parser)

    def add_spc_token_parser(self, subparsers: Any) -> None:
        """Add the generic SPC token parser."""

        parser = subparsers.add_parser(
            "spc-token",
            help="Request and validate a generic STI-PA SPC token",
            description=dedent("""\
                Request and validate an SPC token directly from STI-PA. This is
                provider-neutral token tooling; Peeringhub issuance obtains and
                submits its SPC token internally. Use --fingerprint with the
                SHA256 output from the fingerprint command.
                """),
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        parser.add_argument(
            "--user-id",
            help="STI-PA API user ID; config stipa_user_id or STIPA_USER_ID",
        )
        parser.add_argument(
            "--password",
            help="STI-PA API password; config stipa_password or STIPA_PASSWORD",
        )
        parser.add_argument(
            "--sp-id",
            help=(
                "STI-PA service provider account ID; config stipa_sp_id "
                "or STIPA_SP_ID"
            ),
        )
        parser.add_argument(
            "--spc",
            help="TNAuthList service provider code; config stipa_spc or STIPA_SPC",
        )
        parser.add_argument(
            "--fingerprint",
            help=(
                "ATC fingerprint, for example 'SHA256 AA:BB:...'; config "
                "stipa_atc_fingerprint or STIPA_ATC_FINGERPRINT"
            ),
        )
        parser.add_argument(
            "--staging",
            action="store_true",
            help="Use STI-PA staging instead of production",
        )
        self.add_directory_argument(
            parser, "--output-dir", help="Write SPC token summary artifacts here"
        )
        parser.add_argument(
            "--encoding",
            choices=["base64", "base64url"],
            default="base64",
            help="TNAuthList encoding; base64 is the normal STI-PA value",
        )
        parser.add_argument(
            "--write-token-artifacts",
            action="store_true",
            help=(
                "Also write sensitive JWT/request/response diagnostics when "
                "--output-dir is set"
            ),
        )

    def add_validate_cert_parser(self, subparsers: Any) -> None:
        """Add the certificate validation parser."""

        parser = subparsers.add_parser(
            "validate-cert",
            help="Validate a key/certificate pair",
            description=dedent("""\
                Validate that a local SHAKEN certificate public key matches a
                local EC P-256 private key. This verifies that the certificate
                belongs with the private key file. This command is local-only.
                """),
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        self.add_file_argument(
            parser,
            "--key",
            help="SHAKEN private key path; config shaken_key_path or SHAKEN_KEY_PATH",
            extensions=KEY_EXTENSIONS,
        )
        self.add_file_argument(
            parser,
            "--certificate",
            help=(
                "SHAKEN certificate path; config shaken_certificate_path or "
                "SHAKEN_CERTIFICATE_PATH"
            ),
            extensions=CERTIFICATE_EXTENSIONS,
        )

    def add_peeringhub_account_parser(self, subparsers: Any) -> None:
        """Add the Peeringhub account parser."""

        parser = subparsers.add_parser(
            "peeringhub-account-setup",
            help="Create or verify a Peeringhub ACME account",
            description=dedent("""\
                Prepare or verify a Peeringhub ACME account. The toolkit keeps
                a local ACME account directory containing account.key, which is
                the durable account credential, and account.json, which is a
                recoverable cache of the account URL returned by Peeringhub.
                This command contacts Peeringhub ACME but does not create a
                certificate order.
                """),
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        self.add_peeringhub_environment_args(parser)
        self.add_acme_account_args(parser)

    def add_peeringhub_issue_parser(self, subparsers: Any) -> None:
        """Add the Peeringhub issuance parser."""

        parser = subparsers.add_parser(
            "peeringhub-issue",
            help="Issue a Peeringhub STIR/SHAKEN certificate",
            description=dedent("""\
                Run the full Peeringhub ACME issuance workflow. This command
                builds a CSR from the local ACME account key, requests an
                STI-PA SPC token, submits the ACME challenge to Peeringhub, and
                downloads the issued certificate artifacts. The local ACME
                account key and recoverable account cache are read or created
                under the account directory.
                """),
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        self.add_peeringhub_environment_args(parser)
        self.add_stipa_args(parser)
        self.add_acme_account_args(parser)
        self.add_subject_args(parser)
        parser.add_argument(
            "--spc",
            help="TNAuthList service provider code; config stipa_spc or STIPA_SPC",
        )
        self.add_directory_argument(
            parser,
            "--output-dir",
            help=(
                "New directory for issued certificate artifacts; default is "
                "./shaken-cert-YYYYMMDDTHHMMSSZ"
            ),
        )
        parser.add_argument("--not-before", help="Optional RFC 3339 notBefore")
        parser.add_argument("--not-after", help="Optional RFC 3339 notAfter")

    def add_csr_parser(self, subparsers: Any) -> None:
        """Add the CSR parser."""

        parser = subparsers.add_parser(
            "csr",
            help="Generate a SHAKEN key and CSR",
            description=dedent("""\
                Generate a local EC P-256 SHAKEN private key and PEM CSR with
                a TNAuthList extension. The CSR is suitable for STI-PA and
                ACME workflows. This command is local-only.
                """),
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        self.add_subject_args(parser)
        parser.add_argument(
            "--spc",
            help="TNAuthList service provider code; config stipa_spc or STIPA_SPC",
        )
        self.add_file_argument(
            parser,
            "--key-out",
            help=f"Private key output; built-in default: ./{DEFAULT_SHAKEN_KEY_OUT}",
            extensions=KEY_EXTENSIONS,
        )
        self.add_file_argument(
            parser,
            "--csr-pem-out",
            help=f"PEM CSR output; built-in default: ./{DEFAULT_SHAKEN_CSR_PEM_OUT}",
            extensions=CSR_EXTENSIONS,
        )
        self.add_file_argument(
            parser,
            "--csr-der-out",
            help="Optional binary DER CSR output for systems that require it",
            extensions=(".der",),
        )

    def add_peeringhub_environment_args(self, parser: argparse.ArgumentParser) -> None:
        """Add Peeringhub environment arguments to a parser."""

        parser.add_argument(
            "--environment",
            choices=["staging", "production"],
            help=(
                "Peeringhub environment; config peeringhub_environment or "
                "PEERINGHUB_ENVIRONMENT; built-in default: production"
            ),
        )

    def add_stipa_args(self, parser: argparse.ArgumentParser) -> None:
        """Add STI-PA credential arguments to a parser."""

        parser.add_argument(
            "--stipa-user-id",
            help="STI-PA API user ID; config stipa_user_id or STIPA_USER_ID",
        )
        parser.add_argument(
            "--stipa-password",
            help="STI-PA API password; config stipa_password or STIPA_PASSWORD",
        )
        parser.add_argument(
            "--sp-id",
            help=(
                "STI-PA service provider account ID; config stipa_sp_id "
                "or STIPA_SP_ID"
            ),
        )

    def add_acme_account_args(self, parser: argparse.ArgumentParser) -> None:
        """Add ACME account arguments to a parser."""

        self.add_peeringhub_account_dir_arg(parser)
        parser.add_argument(
            "--kid",
            help=(
                "Peeringhub ACME key identifier / JWK kid; use the value "
                "Peeringhub provides when they provide one; config acme_kid or "
                "ACME_KID"
            ),
        )

    def add_peeringhub_account_dir_arg(self, parser: argparse.ArgumentParser) -> None:
        """Add the Peeringhub local ACME account directory argument."""

        self.add_directory_argument(
            parser,
            "--account-dir",
            help=(
                "Local Peeringhub ACME account directory; contains account.key "
                "and account.json; config acme_account_dir or ACME_ACCOUNT_DIR"
            ),
        )

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

        parser.add_argument(
            "--country",
            help="X.509 subject country; built-in default: US",
        )
        parser.add_argument("--state", help="X.509 subject state or province")
        parser.add_argument("--locality", help="X.509 subject city or locality")
        parser.add_argument("--organization", help="X.509 subject organization name")
        parser.add_argument(
            "--common-name",
            help=(
                "X.509 subject common name for the SHAKEN cert; peeringhub-issue "
                "defaults to SHAKEN <SPC> <timestamp>"
            ),
        )
        parser.add_argument(
            "--organizational-unit", help="Optional X.509 organizational unit"
        )

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
            acme_base_url=defaults.acme_base_url,
            stipa_base_url=defaults.stipa_base_url,
            stipa_crl_url=defaults.stipa_crl_url,
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

    def peeringhub_account_paths(
        self,
        args: argparse.Namespace,
        resolver: CliValueResolver,
        environment: str,
    ) -> PeeringhubAccountPaths:
        """Resolve local Peeringhub ACME account storage paths."""

        account_dir = resolver.path(
            getattr(args, "account_dir", None), "acme_account_dir", "ACME_ACCOUNT_DIR"
        )
        if account_dir is None:
            account_paths = PeeringhubAccountPaths.default(environment)
        else:
            account_paths = PeeringhubAccountPaths.from_account_dir(account_dir)
        LOGGER.debug(
            "Peeringhub account paths resolved: account_dir=%s account_key_path=%s "
            + "account_state_path=%s",
            account_paths.account_dir,
            account_paths.account_key_path,
            account_paths.account_state_path,
        )
        return account_paths

    def peeringhub_stipa_settings(
        self,
        args: argparse.Namespace,
        resolver: CliValueResolver,
        profile: PeeringhubProfile,
    ) -> StipaSettings:
        """Build Peeringhub STI-PA settings from resolved values."""

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
            timeout_seconds=DEFAULT_TIMEOUT_SECONDS,
            minimum_token_lifetime_seconds=DEFAULT_POLL_TIMEOUT_SECONDS,
        )

    def shaken_subject_from_args(
        self,
        args: argparse.Namespace,
        resolver: CliValueResolver,
        common_name_default: str | None = None,
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
                common_name_default,
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

    def resolve_stipa_base_url(self, environment: str) -> str:
        """Resolve a generic STI-PA base URL."""

        return PEERINGHUB_STIPA_URLS[environment]

    def spc_token_output(self, package: StipaTokenPackage) -> dict[str, object]:
        """Build sanitized SPC token CLI output."""

        return {
            "crl_url": package.crl_url,
            "exp": package.exp,
            "fingerprint": package.fingerprint,
            "jti": package.jti,
            "tn_auth_list_value": package.tn_auth_list_value,
            "token": package.token,
            "x5u": package.x5u,
        }

    def write_spc_token_artifacts(
        self,
        output_dir: Path,
        package: StipaTokenPackage,
        write_token_artifacts: bool,
    ) -> None:
        """Write optional SPC token artifacts."""

        output_dir.mkdir(parents=True, exist_ok=True)
        LOGGER.debug("Writing SPC token summary artifact: %s", output_dir)
        self.write_json(
            output_dir / "spc-token-summary.json",
            self.spc_token_summary_output(package),
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
        self.write_text(output_dir / "spc-token.jwt", f"{package.token}\n", 0o600)

    def spc_token_summary_output(self, package: StipaTokenPackage) -> dict[str, object]:
        """Build SPC token summary output without the sensitive token."""

        return {
            "crl_url": package.crl_url,
            "exp": package.exp,
            "fingerprint": package.fingerprint,
            "jti": package.jti,
            "tn_auth_list_value": package.tn_auth_list_value,
            "x5u": package.x5u,
        }

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
                "certificate_details": (
                    result.certificate_details.as_dict()
                    if result.certificate_details is not None
                    else None
                ),
                "certificate_private_key_path": str(result.certificate_key_path),
                "certificate_private_key_source": "peeringhub_acme_account_key",
                "certificate_url": result.certificate_url,
                "finalize_url": result.finalize_url,
                "order_url": result.order_url,
                "stipa_token_exp": result.stipa_token.exp,
                "stipa_token_jti": result.stipa_token.jti,
                "tn_auth_list_value": result.tn_auth_list_value,
                "validation_error": result.validation_error,
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
