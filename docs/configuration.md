# Configuration

`stir-shaken-toolkit` can read values from command-line arguments, a YAML config
file, environment variables, and built-in defaults.

Values resolve in this order:

1. Explicit command-line arguments.
2. `--config` YAML values.
3. Prefixed environment variables.
4. Built-in defaults.

`--config` is a global option, so place it before the subcommand:

```bash
stir-shaken-toolkit --config toolkit.yaml peeringhub-issue
```

Environment variables use only domain prefixes such as `STIPA_*`, `ACME_*`,
`SHAKEN_*`, and `PEERINGHUB_*`.

## Config Keys

The YAML config uses flat keys. Environment variables use the uppercase names
shown below.

| Config key | Environment variable | Purpose | Used by |
| --- | --- | --- | --- |
| `stipa_spc` | `STIPA_SPC` | Four-character TNAuthList service provider code. | `spc-token`, `peeringhub-issue`, `csr` |
| `stipa_user_id` | `STIPA_USER_ID` | STI-PA API user ID. | `spc-token`, `ca-list`, `peeringhub-issue` |
| `stipa_password` | `STIPA_PASSWORD` | STI-PA API password. | `spc-token`, `ca-list`, `peeringhub-issue` |
| `stipa_sp_id` | `STIPA_SP_ID` | STI-PA STI Participant ID. | `spc-token`, `peeringhub-issue` |
| `stipa_environment` | `STIPA_ENVIRONMENT` | STI-PA environment: `staging` or `production`. | `spc-token`, `ca-list`, PeeringHub fallback |
| `stipa_atc_fingerprint` | `STIPA_ATC_FINGERPRINT` | Account/public-key fingerprint for standalone SPC token requests. | `spc-token` |
| `stipa_output_dir` | `STIPA_OUTPUT_DIR` | Directory for standalone SPC token summary artifacts. | `spc-token` |
| `acme_account_dir` | `ACME_ACCOUNT_DIR` | Local PeeringHub account directory containing `account.key` and `account.json`. | `fingerprint`, PeeringHub commands |
| `acme_kid` | `ACME_KID` | PeeringHub ACME key identifier / JWK `kid`. | PeeringHub commands |
| `peeringhub_environment` | `PEERINGHUB_ENVIRONMENT` | PeeringHub environment: `staging` or `production`. | PeeringHub commands |
| `shaken_subject_country` | `SHAKEN_SUBJECT_COUNTRY` | X.509 subject country; defaults to `US`. | `peeringhub-issue`, `csr` |
| `shaken_subject_state` | `SHAKEN_SUBJECT_STATE` | X.509 subject state or province. | `peeringhub-issue`, `csr` |
| `shaken_subject_locality` | `SHAKEN_SUBJECT_LOCALITY` | X.509 subject city or locality. | `peeringhub-issue`, `csr` |
| `shaken_subject_organization` | `SHAKEN_SUBJECT_ORGANIZATION` | X.509 subject organization name. | `peeringhub-issue`, `csr` |
| `shaken_subject_common_name` | `SHAKEN_SUBJECT_COMMON_NAME` | X.509 subject common name. | `peeringhub-issue`, `csr` |
| `shaken_subject_organizational_unit` | `SHAKEN_SUBJECT_ORGANIZATIONAL_UNIT` | Optional X.509 subject organizational unit. | `peeringhub-issue`, `csr` |
| `shaken_private_key_path` | `SHAKEN_PRIVATE_KEY_PATH` | Private key to match against a certificate or CSR. | `validate-key-pair` |
| `shaken_certificate_path` | `SHAKEN_CERTIFICATE_PATH` | Certificate to validate against the private key. | `validate-key-pair` |
| `shaken_csr_path` | `SHAKEN_CSR_PATH` | CSR to validate against the private key. | `validate-key-pair` |
| `shaken_output_dir` | `SHAKEN_OUTPUT_DIR` | New directory for PeeringHub issuance artifacts. | `peeringhub-issue` |
| `shaken_key_out` | `SHAKEN_KEY_OUT` | Generated CSR private key output; defaults to `shaken.key`. | `csr` |
| `shaken_csr_pem_out` | `SHAKEN_CSR_PEM_OUT` | Generated PEM CSR output; defaults to `shaken.csr`. | `csr` |
| `shaken_csr_der_out` | `SHAKEN_CSR_DER_OUT` | Optional generated DER CSR output. | `csr` |
| `shaken_not_before` | `SHAKEN_NOT_BEFORE` | Optional RFC 3339 ACME order `notBefore`. | `peeringhub-issue` |
| `shaken_not_after` | `SHAKEN_NOT_AFTER` | Optional RFC 3339 ACME order `notAfter`. | `peeringhub-issue` |

## Environment Selection

`peeringhub_environment` has priority for PeeringHub commands. If it is unset,
those commands also accept `stipa_environment` as a fallback. Both values must
be `staging` or `production`; `production` is the built-in default when a
command allows a default.

For `spc-token` and `ca-list`, production is the default and `--staging`
selects the staging STI-PA URL from the command line.

## Account Directory Defaults

PeeringHub ACME commands use one local account directory. If
`acme_account_dir` is unset, the toolkit uses a per-user platform default:

- Linux: `$XDG_STATE_HOME/stir-shaken-toolkit/peeringhub/<environment>` or
  `~/.local/state/stir-shaken-toolkit/peeringhub/<environment>`.
- macOS: `~/Library/Application Support/stir-shaken-toolkit/peeringhub/<environment>`.
- Windows: `%LOCALAPPDATA%\stir-shaken-toolkit\peeringhub\<environment>`.

The directory contains:

- `account.key`: the durable local EC P-256 ACME account private key.
- `account.json`: a recoverable cache of the ACME account URL returned by
  PeeringHub.

If `account.json` is removed, the toolkit recreates it by authorizing with
PeeringHub using the existing key. If `account.json` exists but `account.key` is
missing, the toolkit fails because it cannot sign requests for the cached
account.

PeeringHub may provide or confirm the `acme_kid` value, but PeeringHub does not
provide either local file.

## CLI and Python Boundaries

The CLI keeps protocol tuning out of normal operator workflows. HTTP timeouts,
badNonce retries, ACME polling, ACME/STI-PA endpoint overrides, expected CRL URL
checks, and certificate lifetime validation thresholds remain configurable from
Python APIs for tests and custom integrations.

## Example Config

```yaml
stipa_spc: 818H
stipa_user_id: sti-pa-user
stipa_password: sti-pa-password
stipa_sp_id: 818H
peeringhub_environment: staging
acme_account_dir: /secure/peeringhub-account
acme_kid: peeringhub-kid
shaken_output_dir: /secure/shaken-output
shaken_subject_country: US
shaken_subject_state: Example
shaken_subject_locality: Example
shaken_subject_organization: Example Telecom
shaken_subject_common_name: SHAKEN 818H generation-1
```
