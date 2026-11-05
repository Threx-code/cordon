# Real Sigstore attestations

Public attestations, unmodified, one per shape the verifier reads, fetched in October 2026:

- `npm-provenance-dsse.json`, `npm-provenance-intoto.json`, `npm-provenance-v0.1.json`,
  `npm-publish.json`: from `https://registry.npmjs.org/-/npm/v1/attestations/<name>@<version>`,
  with the package, version and the statement's subject digest alongside the bundle.
- `maven-message-signature.json`: `dev.sigstore:sigstore-java:1.3.0`'s `.jar.sigstore.json` from
  Maven Central, with the jar's SHA-256.
- `pypi-pep740.json`: urllib3 2.5.0's PEP 740 provenance from `https://pypi.org/integrity/`,
  with the wheel's SHA-256.
- `pypi-cordon-scanner-0.6.0-provenance.json`: Cordon's own 0.6.0 wheel's PEP 740 provenance from
  `https://pypi.org/integrity/` (fetched 3 November 2026), with the wheel's SHA-256: what `verify`'s
  online step checks against the release workflow's identity.

The verifier's tests check each verifies, and that each tampered form does not.
