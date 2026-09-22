# 05 · Provenance & attestation — prove the source

An attestation is a **signed receipt** a build system produces at publish time:
*"this exact file was built by github.com/acme/lib, at this commit, by its CI."*

```
   pip install cordon-scanner[attest]
   cordon-scanner scan . --online
```

## The attack it stops

```
   THE STOLEN-TOKEN ATTACK
   ┌────────────────────────────────────────────────────────────────────────┐
   │  attacker steals a publish token, uploads a malicious version.          │
   │  it STILL names the honest repo (github.com/acme/lib) in its metadata.  │
   └────────────────────────────────────────────────────────────────────────┘

   presence check only:   "does it carry a receipt?"     ── an attacker can attach one
   FULL verification:     "is the receipt real, AND does the signer's identity
                           match the repo it claims?"     ── the attacker CANNOT forge this
```

## Base vs [attest]

```
   BASE  (always)                          [attest]  (opt-in, --online)
   ─────────────                           ────────────────────────────
   sees an attestation is PRESENT          VERIFIES the sigstore bundle:
   (npm dist.attestations,                   • Fulcio  certificate
    PyPI PEP 740)                            • Rekor   transparency-log inclusion
   flags a suspicious ABSENCE               • DSSE    signature over the pinned digest
   POLICY.PROVENANCE.UNVERIFIED             • identity = the DECLARED source repo
```

## The verification path

```
   dependency (advertises attestation)
        │
        ▼
   fetch the sigstore bundle the registry points at   ── host-allowlisted
        │
        ▼
   verify_artifact( bundle, digest = LOCKFILE's pinned hash, policy = repo identity )
        │                              └── a registry swap shows up here as a failure
        │
   ┌────┴─────────────┬────────────────────────┐
   VERIFIED           INVALID                   UNVERIFIABLE
   (no finding)       VULNERABLE.PROVENANCE     POLICY.PROVENANCE
                      .INVALID (critical)        .UNVERIFIED  (low)
                      sig/identity rejected      extra absent, no digest,
                                                 or no usable bundle
```

## "Checked and failed" ≠ "could not check"

```
   INVALID       →  act on it. The signature or the identity is wrong.
   UNVERIFIABLE  →  install [attest], pin the digest, or accept provenance is
                    asserted rather than proven. Never a false pass, never a crash.
```

## Why an extra

```
   Real verification needs a Fulcio+Rekor+DSSE crypto stack (sigstore). The base
   takes ZERO third-party runtime deps, so that stack lives in [attest]. It also
   needs the network + a trust root, which is why the check is --online only.
```

Next: **06 — the advisory database**.
