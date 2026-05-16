# PeeringHub Issuance

The PeeringHub commands wrap the STIR/SHAKEN ACME workflow for operators who
already have STI-PA credentials and PeeringHub ACME access.

## Account Setup

Run account setup before issuing certificates:

```bash
stir-shaken-toolkit peeringhub-account-setup
```

The command prepares or verifies the local PeeringHub ACME account directory.
It contacts PeeringHub ACME but does not create a certificate order.

The directory contains:

- `account.key`: the durable EC P-256 private key used to authenticate ACME
  requests.
- `account.json`: a recoverable cache of the account URL returned by
  PeeringHub.

If PeeringHub gives you a key identifier, pass it with `--kid` or configure
`acme_kid` / `ACME_KID`. PeeringHub does not provide the local private key; the
toolkit creates or reads it locally.

## Key Model

PeeringHub issuance uses the same `account.key` for:

- ACME JWS signing.
- The STI-PA SPC token fingerprint.
- The certificate CSR public key.
- The final certificate/private-key pair.

This means the issued certificate belongs with `account.key`. The issuance
output directory intentionally does not contain another private key.

## Issue a Certificate

```bash
stir-shaken-toolkit peeringhub-issue
```

The command:

1. Prepares or verifies the ACME account.
2. Builds the TNAuthList value from the configured SPC.
3. Requests and validates an STI-PA SPC token.
4. Creates a PeeringHub ACME order.
5. Submits the `tkauth-01` challenge.
6. Builds a CSR from the local ACME account key.
7. Downloads and validates the issued certificate chain.

If no `shaken_subject_common_name`, `SHAKEN_SUBJECT_COMMON_NAME`, or
`--common-name` is provided, `peeringhub-issue` uses
`SHAKEN <SPC> <timestamp>`. This avoids PeeringHub's duplicate-subject
restriction during repeated CLI issuance.

`peeringhub-issue` omits CRL Distribution Points from the CSR so PeeringHub can
add the official PA CRL extension during issuance.

## Output Directory

`peeringhub-issue` writes issued certificate artifacts to `shaken_output_dir`,
`SHAKEN_OUTPUT_DIR`, or `--output-dir` when configured. If none is set, it
creates a new timestamped directory in the current working directory, for
example:

```text
./shaken-cert-20260508T162900Z
```

See [Artifacts and Installation](artifacts.md) for the file list and install
guidance.

## Diagnostics

Use `--debug` at the top level for detailed diagnostics with secrets redacted:

```bash
stir-shaken-toolkit --debug peeringhub-issue
```

Common failures:

- Missing `account.key`: the toolkit cannot authenticate as the PeeringHub ACME
  account.
- Duplicate subject: PeeringHub already has a valid certificate with the same
  subject name.
- Invalid CSR: PeeringHub rejected the CSR after ACME challenge validation.
- Local validation failure: the certificate was downloaded but did not pass
  toolkit validation.

When certificate download succeeds but local validation fails, the CLI writes
failure artifacts to the output directory so the returned certificate can be
inspected.

Issued certificate validation requires a certificate policy OID under the
STI-PA SHAKEN policy arc `2.16.840.1.114569.1.1` by default. Python callers can
set `accepted_shaken_policy_oids` on `ShakenCertificatePolicy` for stricter
exact-OID validation.
