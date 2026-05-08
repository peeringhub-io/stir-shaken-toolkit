# STIR/SHAKEN Toolkit

Reusable Python toolkit for STIR/SHAKEN certificate issuance.

## Package Layers

- `acme_core`: provider-neutral RFC 8555 ACME primitives.
- `stir_shaken_acme`: TNAuthList, STI-PA tokens, fingerprints, CSRs, and
  certificate validation.
- `stir_shaken_toolkit.providers.peeringhub`: Peeringhub profile defaults and convenience issuer.

## Python Usage

```python
from pathlib import Path

from stir_shaken_acme import (
    ShakenCertificatePolicy,
    ShakenSubject,
    StipaSettings,
    TnAuthList,
)
from stir_shaken_toolkit.providers.peeringhub import PeeringhubIssuer, PeeringhubProfile

profile = PeeringhubProfile.for_environment("staging")
tn_auth_list = TnAuthList("818H")
policy = ShakenCertificatePolicy(
    subject=ShakenSubject(
        country="US",
        state="Example",
        locality="Example",
        organization="Example Telecom generation-1",
        common_name="SHAKEN 818H generation-1",
    ),
    tn_auth_list_der=tn_auth_list.der(),
    expected_crl_url=profile.stipa_crl_url,
    critical_days=21,
)
issuer = PeeringhubIssuer.build(
    profile=profile,
    account_key_path=Path("/secure/acme-account.key"),
    account_state_path=Path("/secure/account.json"),
    acme_kid="example-staging",
    stipa_settings=StipaSettings(
        base_url=profile.stipa_base_url,
        user_id="sti-pa-user",
        password="sti-pa-password",
        sp_id="818H",
        expected_crl_url=profile.stipa_crl_url,
    ),
    certificate_policy=policy,
)
```

Live issuance uses `issuer.issue(...)` and should only be run from an
operator-controlled environment with valid STI-PA credentials.

## CLI Configuration

CLI values resolve in this order:

1. Explicit command-line arguments.
2. `--config` YAML values.
3. Prefixed environment variables.
4. Built-in defaults.

Environment variables use only domain prefixes such as `STIPA_*`, `ACME_*`,
`SHAKEN_*`, and `PEERINGHUB_*`.

`--config` is a global option, so place it before the subcommand:

```bash
stir-shaken-toolkit --config toolkit.yaml peeringhub-issue
```

### Config Keys

The YAML config uses flat keys. Environment variables use the uppercase names
shown below.

| Config key | Environment variable | Used by |
| --- | --- | --- |
| `stipa_spc` | `STIPA_SPC` | `tnauth`, `spc-token`, `peeringhub-issue`, `csr` |
| `stipa_user_id` | `STIPA_USER_ID` | `spc-token`, `peeringhub-issue` |
| `stipa_password` | `STIPA_PASSWORD` | `spc-token`, `peeringhub-issue` |
| `stipa_sp_id` | `STIPA_SP_ID` | `spc-token`, `peeringhub-issue` |
| `stipa_environment` | `STIPA_ENVIRONMENT` | `spc-token`, Peeringhub fallback |
| `stipa_base_url` | `STIPA_BASE_URL` | `spc-token` |
| `stipa_expected_crl_url` | `STIPA_EXPECTED_CRL_URL` | `spc-token` |
| `stipa_timeout_seconds` | `STIPA_TIMEOUT_SECONDS` | `spc-token`, `peeringhub-issue` |
| `stipa_atc_fingerprint` | `STIPA_ATC_FINGERPRINT` | `spc-token` |
| `stipa_output_dir` | `STIPA_OUTPUT_DIR` | `spc-token` |
| `acme_account_key_path` | `ACME_ACCOUNT_KEY_PATH` | `fingerprint`, Peeringhub commands |
| `acme_account_state_path` | `ACME_ACCOUNT_STATE_PATH` | Peeringhub commands |
| `acme_kid` | `ACME_KID` | Peeringhub commands |
| `acme_timeout_seconds` | `ACME_TIMEOUT_SECONDS` | Peeringhub commands |
| `acme_bad_nonce_retries` | `ACME_BAD_NONCE_RETRIES` | Peeringhub commands |
| `acme_poll_interval_seconds` | `ACME_POLL_INTERVAL_SECONDS` | `peeringhub-issue` |
| `acme_poll_timeout_seconds` | `ACME_POLL_TIMEOUT_SECONDS` | `peeringhub-issue` |
| `peeringhub_environment` | `PEERINGHUB_ENVIRONMENT` | Peeringhub commands |
| `peeringhub_acme_base_url` | `PEERINGHUB_ACME_BASE_URL` | Peeringhub commands |
| `peeringhub_stipa_base_url` | `PEERINGHUB_STIPA_BASE_URL` | `peeringhub-issue` |
| `peeringhub_stipa_crl_url` | `PEERINGHUB_STIPA_CRL_URL` | `peeringhub-issue` |
| `shaken_subject_country` | `SHAKEN_SUBJECT_COUNTRY` | `peeringhub-issue`, `csr` |
| `shaken_subject_state` | `SHAKEN_SUBJECT_STATE` | `peeringhub-issue`, `csr` |
| `shaken_subject_locality` | `SHAKEN_SUBJECT_LOCALITY` | `peeringhub-issue`, `csr` |
| `shaken_subject_organization` | `SHAKEN_SUBJECT_ORGANIZATION` | `peeringhub-issue`, `csr` |
| `shaken_subject_common_name` | `SHAKEN_SUBJECT_COMMON_NAME` | `peeringhub-issue`, `csr` |
| `shaken_subject_organizational_unit` | `SHAKEN_SUBJECT_ORGANIZATIONAL_UNIT` |  `peeringhub-issue`, `csr` |
| `shaken_key_path` | `SHAKEN_KEY_PATH` | `validate-cert` |
| `shaken_certificate_path` | `SHAKEN_CERTIFICATE_PATH` | `validate-cert` |
| `shaken_output_dir` | `SHAKEN_OUTPUT_DIR` | `peeringhub-issue` |
| `shaken_key_out` | `SHAKEN_KEY_OUT` | `csr`; defaults to `shaken.key` |
| `shaken_csr_pem_out` | `SHAKEN_CSR_PEM_OUT` | `csr`; defaults to `shaken.csr` |
| `shaken_csr_der_out` | `SHAKEN_CSR_DER_OUT` | `csr`; optional DER output |
| `shaken_crl_url` | `SHAKEN_CRL_URL` | `csr` |
| `shaken_critical_days` | `SHAKEN_CRITICAL_DAYS` | `peeringhub-issue` |
| `shaken_not_before` | `SHAKEN_NOT_BEFORE` | `peeringhub-issue` |
| `shaken_not_after` | `SHAKEN_NOT_AFTER` | `peeringhub-issue` |

`peeringhub_environment` has priority for Peeringhub commands. If it is unset,
those commands also accept `stipa_environment` as a fallback. Both values must be
`staging` or `production`; `production` is the built-in default when a command
allows a default. For `spc-token`, production is the default and `--staging`
selects the staging STI-PA URL from the command line.

Default timeout values are 30 seconds for HTTP calls, 2 badNonce retries,
5 seconds between ACME order polls, 180 seconds total ACME poll time, and
21 days for the issued-certificate critical threshold used by
`peeringhub-issue`.

`stipa_base_url` can be a single URL or an environment-keyed mapping:

```yaml
stipa_base_url:
  staging: https://sti-pa.example.test
  production: https://sti-pa.example.com
```

Peeringhub provider URLs can use the explicit `peeringhub_*` keys above. For
YAML config only, the provider resolver also accepts environment-keyed
`acme_base_url`, `stipa_base_url`, and `stipa_crl_url` mappings.

```yaml
peeringhub_environment: staging
acme_base_url:
  staging: https://acme-staging.example.com/acme
  production: https://acme.example.com/acme
stipa_base_url:
  staging: https://sti-pa-staging.example.com
  production: https://sti-pa.example.com
stipa_crl_url:
  staging: https://sti-pa-staging.example.com/stipa.crl
  production: https://sti-pa.example.com/stipa.crl
```

### Config Example

```yaml
stipa_spc: 818H
stipa_user_id: sti-pa-user
stipa_password: sti-pa-password
stipa_sp_id: 818H
peeringhub_environment: staging
acme_account_key_path: /secure/acme-account.key
acme_account_state_path: /secure/acme-account.json
acme_kid: apartment-lines-staging
shaken_output_dir: /secure/shaken-output
shaken_subject_country: US
shaken_subject_state: Example
shaken_subject_locality: Example
shaken_subject_organization: Example Telecom
shaken_subject_common_name: SHAKEN 818H generation-1
```

## CLI Usage

```bash
stir-shaken-toolkit tnauth --spc 818H
stir-shaken-toolkit fingerprint --private-key /secure/acme-account.key
stir-shaken-toolkit spc-token \
  --user-id "$STIPA_USER_ID" \
  --password "$STIPA_PASSWORD" \
  --sp-id 818H \
  --spc 818H \
  --fingerprint "SHA256 AA:BB:..."
stir-shaken-toolkit peeringhub-account-status --help
stir-shaken-toolkit peeringhub-issue --help
stir-shaken-toolkit csr --spc 818H
```

`spc-token` is generic STI-PA token tooling. Peeringhub certificate issuance
creates and consumes the required SPC token internally during `peeringhub-issue`.
`tnauth` defaults to padded standard base64 for STI-PA `tkvalue` usage. Use
`--encoding base64url` only when an unpadded base64url value is needed for
another protocol context.
`csr` is local key and CSR generation; it does not expose provider environment
selection, writes `shaken.key` and `shaken.csr` in the current directory by
default, and includes CRL Distribution Points only when a CRL URL is provided.
Use `--csr-der-out` only when a DER CSR is needed.

## Shell Completion

The CLI supports generated shell completion through `argcomplete`. For bash,
enable completion in the current shell with:

```bash
eval "$(register-python-argcomplete stir-shaken-toolkit)"
```

To enable it persistently, add that line to your shell startup file after the
toolkit is installed in the environment used by your shell. Completion is
derived from the argparse CLI definitions, so new subcommands and options do
not require a hand-maintained completion script.

Path arguments include file-aware completions where useful. For example,
certificate inputs complete `.crt` and `.pem` files, CSR inputs complete `.csr`
and `.pem` files, key inputs complete `.key` and `.pem` files, config inputs
complete `.yaml` and `.yml` files, and output directory arguments complete
directories.
