# Python API

The toolkit can be used as a Python library when the CLI is too narrow for an
integration.

## Package Layers

- `acme_core`: provider-neutral RFC 8555 ACME primitives.
- `stir_shaken_acme`: TNAuthList, STI-PA tokens, fingerprints, CSRs,
  certificate issuance, and certificate validation.
- `stir_shaken_toolkit.providers.peeringhub`: Peeringhub profile defaults and a
  convenience issuer.

## Peeringhub Example

```python
from pathlib import Path

from stir_shaken_acme import (
    ShakenCertificatePolicy,
    ShakenSubject,
    StipaSettings,
    TnAuthList,
)
from stir_shaken_toolkit.providers.peeringhub import (
    PeeringhubIssuer,
    PeeringhubProfile,
)

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
    minimum_certificate_lifetime_days=21,
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
        sp_id="818H",  # STI-PA STI Participant ID
        expected_crl_url=profile.stipa_crl_url,
    ),
    certificate_policy=policy,
)
```

Live issuance uses `issuer.issue(...)` and should only be run from an
operator-controlled environment with valid STI-PA credentials.

## Advanced Options

The Python API exposes lower-level controls that are intentionally hidden from
the normal CLI, including:

- ACME and STI-PA endpoint overrides.
- HTTP timeouts.
- `badNonce` retry behavior.
- ACME polling intervals and timeouts.
- Expected CRL URL checks.
- Exact accepted SHAKEN policy OIDs through
  `ShakenCertificatePolicy.accepted_shaken_policy_oids`.

Use these options for tests, custom integrations, or provider-specific work
where the CLI defaults are too opinionated.
