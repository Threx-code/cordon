# 05 · Provenance & attestation — prove the source

> **For Cordon 0.6.0.** Using another version? Open the tutorials at its tag: `https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` prints the link for the version you have installed.

An attestation is a **signed receipt** a build system produces at publish time:
*"this exact file was built by github.com/acme/lib, at this commit, by its CI."*

```
   cordon-scanner scan . --online
```

## The attack it stops

```
   THE STOLEN-TOKEN ATTACK
   ┌────────────────────────────────────────────────────────────────────────┐
   │  attacker steals a publish token, uploads a malicious version.         │
   │  it STILL names the honest repo (github.com/acme/lib) in its metadata. │
   └────────────────────────────────────────────────────────────────────────┘

   presence check only:   "does it carry a receipt?"     ── an attacker can attach one
   FULL verification:     "is the receipt real, AND does the signer's identity
                           match the repo it claims?"     ── the attacker CANNOT forge this
```

## Offline vs --online

```
   OFFLINE  (always)                       --online
   ─────────────────                       ────────
   sees an attestation is PRESENT          VERIFIES the sigstore bundle:
   (npm dist.attestations,                   • Fulcio  certificate + CT timestamp
    PyPI PEP 740)                            • Rekor   inclusion proof + checkpoint
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
   verify( bundle, digest = LOCKFILE's pinned hash, identity = declared repo )
        │                              └── a registry swap shows up here as a failure
        │
   ┌────┴─────────────┬────────────────────────┐
   VERIFIED           INVALID                   UNVERIFIABLE
   (no finding)       VULNERABLE.PROVENANCE     POLICY.PROVENANCE
                      .INVALID (critical)        .UNVERIFIED  (low)
                      sig/identity rejected      no digest, or no
                                                 usable bundle
```

## "Checked and failed" ≠ "could not check"

```
   INVALID       →  act on it. The signature or the identity is wrong.
   UNVERIFIABLE  →  pin the digest, or accept provenance is
                    asserted rather than proven. Never a false pass, never a crash.
```

## Cordon's own verifier

```
   The Fulcio + Rekor + DSSE checks are Cordon's own code, against a trust root
   it pins -- no third-party crypto, nothing to install. The bundle is fetched
   from the registry, which is why the check is --online only.
```

Next: **[06 · Secrets, credentials and exfiltration](06-secrets-and-exfiltration.md)**.
