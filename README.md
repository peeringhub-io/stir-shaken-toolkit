# STIR/SHAKEN Toolkit

Reusable Python tooling for STIR/SHAKEN certificate work:

- Local utilities for CSRs, fingerprints, certificate validation, and STI-PA
  SPC tokens.
- A Peeringhub ACME workflow for issuing STIR/SHAKEN certificates.
- Python modules that can be reused by higher-level automation.

The package is split into three layers:

- `acme_core`: provider-neutral RFC 8555 ACME primitives.
- `stir_shaken_acme`: STIR/SHAKEN-specific TNAuthList, STI-PA, CSR,
  fingerprint, issuance, and validation helpers.
- `stir_shaken_toolkit.providers.peeringhub`: Peeringhub profile defaults and
  issuance convenience APIs.

## Install

From the repository root:

```bash
python -m pip install -e .
```

## Quick Start

Most operators using Peeringhub need four groups of values:

- STI-PA credentials: `STIPA_USER_ID`, `STIPA_PASSWORD`, and `STIPA_SP_ID`.
- The service provider code: `STIPA_SPC`.
- The Peeringhub ACME key identifier, when Peeringhub provides one:
  `ACME_KID`.
- X.509 subject details such as organization, state, locality, and country.

Values can be supplied as CLI arguments, YAML config, or environment variables.
For repeated use, a config file or environment variables are usually less noisy
than long command lines.

```bash
export STIPA_USER_ID=sti-pa-user
export STIPA_PASSWORD=sti-pa-password
export STIPA_SP_ID=818H
export STIPA_SPC=818H
export ACME_KID=peeringhub-kid
export SHAKEN_SUBJECT_ORGANIZATION="Example Telecom"
export SHAKEN_SUBJECT_STATE=TX
export SHAKEN_SUBJECT_LOCALITY=Irving
```

Prepare or verify the Peeringhub ACME account:

```bash
stir-shaken-toolkit peeringhub-account-setup
```

Issue a certificate:

```bash
stir-shaken-toolkit peeringhub-issue
```

By default, issuance writes artifacts to a new timestamped directory such as
`./shaken-cert-20260508T162900Z`.

`peeringhub-account-setup` and `peeringhub-issue` contact Peeringhub ACME.
`peeringhub-issue` also contacts STI-PA.

## Common Commands

Peeringhub issuance:

```bash
stir-shaken-toolkit peeringhub-account-setup
stir-shaken-toolkit peeringhub-issue
```

Local CSR and fingerprint utilities:

```bash
stir-shaken-toolkit csr --spc 818H
stir-shaken-toolkit fingerprint --csr shaken.csr
stir-shaken-toolkit validate-key-pair --key account.key --certificate leaf.pem
stir-shaken-toolkit validate-key-pair --key shaken.key --csr shaken.csr
```

Standalone STI-PA SPC token request:

```bash
stir-shaken-toolkit spc-token \
  --spc 818H \
  --fingerprint "SHA256 AA:BB:..."
```

List STI-PA STI-CA companies:

```bash
stir-shaken-toolkit ca-list
stir-shaken-toolkit ca-list --json --details
```

Run `stir-shaken-toolkit --help` or
`stir-shaken-toolkit <command> --help` for the current command-line reference.

## Configuration Basics

CLI values resolve in this order:

1. Explicit command-line arguments.
2. `--config` YAML values.
3. Prefixed environment variables.
4. Built-in defaults.

Environment variables use domain prefixes: `STIPA_*`, `ACME_*`, `SHAKEN_*`,
and `PEERINGHUB_*`.

`--config` is a global option, so place it before the subcommand:

```bash
stir-shaken-toolkit --config toolkit.yaml peeringhub-issue
```

See [Configuration](docs/configuration.md) for the complete config and
environment variable reference.

## Important Files

Peeringhub ACME commands use a local account directory. If you do not configure
one, the toolkit chooses a per-user platform default.

The durable credential is `account.key`. Protect it like any other private key.
Peeringhub issuance uses this key for ACME account authentication, the STI-PA
SPC token fingerprint, the CSR public key, and the final certificate/private-key
pair.

The `account.json` file is a recoverable cache of the Peeringhub ACME account
URL. If it is removed, the toolkit can recreate it by signing with the existing
`account.key`.

Peeringhub issuance writes certificate artifacts but does not write a private
key into the issuance output directory. The issued certificate belongs with the
ACME account key.

For installation and publication details, see [Artifacts and Installation](docs/artifacts.md).

## More Documentation

- [Configuration](docs/configuration.md): config keys, environment variables,
  defaults, and examples.
- [Peeringhub Issuance](docs/peeringhub.md): account setup, issuance behavior,
  and common failure diagnostics.
- [Artifacts and Installation](docs/artifacts.md): output files and which
  certificate file to publish for STIR/SHAKEN use.
- [Python API](docs/python-api.md): using the reusable modules directly.
- [Shell Completion](docs/shell-completion.md): generated completion through
  `argcomplete`.
