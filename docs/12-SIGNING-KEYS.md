# Signing keys

Every key that signs something a Cordon client trusts, and how to check it. Generated from the
keys pinned in this build by `python tests/signing_keys.py`; a test fails if this page and the
pinned files disagree.

## Release artefacts: Sigstore, no long-lived key

The wheel, the sdist and the container image are signed keyless by the release workflow. There
is no fingerprint to publish: what you verify is the identity that signed, which only that
workflow in this repository can present.

```bash
# the container image
cosign verify ghcr.io/threx-code/cordon@sha256:<digest> \
  --certificate-identity-regexp '^https://github.com/Threx-code/cordon/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# the wheel and sdist (build provenance)
gh attestation verify cordon_scanner-<version>-py3-none-any.whl --repo Threx-code/cordon
```

## Intel feed root

**Not pinned in this build.** The feed root is created at the key ceremony
(`scripts/key_ceremony.py`) and committed as `src/cordon_scanner/intel/data/feed-root.json`.
Until then the feed is off: a scan makes no request and uses the installed advisory database.

## Advisory database bundle

**Not pinned in this build.** Created at the key ceremony and committed as
`src/cordon_scanner/intel/data/advisory-signing-key.json`. Until then
`advisories sync --bundle` refuses to install a downloaded bundle; `advisories sync`
builds the database locally instead.
