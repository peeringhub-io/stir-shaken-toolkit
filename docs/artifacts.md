# Artifacts and Installation

`peeringhub-issue` writes certificate artifacts to a new output directory unless
`--output-dir`, `shaken_output_dir`, or `SHAKEN_OUTPUT_DIR` is configured.

## Output Files

- `csr.pem`: the PEM CSR submitted to PeeringHub.
- `csr.der`: the DER form of the CSR submitted to PeeringHub.
- `leaf.pem`: the issued subscriber certificate.
- `certificate-chain.pem`: the issued subscriber certificate followed by the
  PeeringHub intermediate certificate.
- `issuance.json`: order URLs, certificate URLs, validation details, subject
  details, and the account key path used for the certificate CSR.

The output directory does not contain a private key. For PeeringHub issuance,
the private key is the local ACME account key, usually named `account.key`.

## Leaf Certificate vs Certificate Chain

`leaf.pem` contains only the certificate issued for your SHAKEN identity.

`certificate-chain.pem` contains the leaf certificate first, followed by the
PeeringHub intermediate certificate. That is normally the file to publish at
the STIR/SHAKEN certificate URL used in PASSporT `x5u`, because verifiers need
the leaf certificate and may need the intermediate to build a trust path.

The private key configured in the signing system must correspond to the public
key in the leaf certificate. For PeeringHub issuance, that is the ACME account
private key.

## Signing System Install Shape

A signing system needs:

- The private key locally, readable only by the signing service.
- A public HTTPS URL that serves the certificate chain PEM.
- STIR/SHAKEN configuration that points to the private key and public
  certificate URL.

Do not publish or expose `account.key`.

## Validation Failures

If PeeringHub issues a certificate but local validation fails, the CLI still
writes the downloaded certificate artifacts and `issuance.json`. This makes the
certificate inspectable without repeating the issuance attempt.

Inspect retained artifacts locally:

```bash
stir-shaken-toolkit inspect --csr csr.pem
stir-shaken-toolkit inspect --certificate leaf.pem
stir-shaken-toolkit inspect --certificate certificate-chain.pem --json
```
