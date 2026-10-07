# 11 · Air-gapped installs

> **For Cordon 0.6.0.** Using another version? Open the tutorials at its tag: `https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` prints the link for the version you have installed.

Cordon never sends anything about the code it scans, which makes an air-gap the
easy case, not the hard one. In 0.5.0 a default scan makes no network request at
all: the signed public intel feed stays off until its root key is pinned in a
release, and intel comes from the advisory database installed with the package.
Set `CORDON_OFFLINE=1` (or pass `--offline`) on an air-gapped runner anyway, so the
scan stays offline once a release turns the feed on, and refresh intel with the
bundle installed below.

```
   INTERNET SIDE                    │  AIR GAP │              SECURE SIDE
   ─────────────                    │          │              ──────────
   cordon-scanner bundle create ───▶│  copy    │───▶ cordon-scanner bundle verify
     (wheel + rules + advisories)   │  the     │     cordon-scanner bundle install
                                    │  bundle  │              │
                                    │          │              ▼
                                    │          │        scan, fully offline
```

## Build, carry, verify, install

```
   bundle create  -o cordon-bundle.tar  <source-dir>    build a bundle from a dir
   bundle verify     cordon-bundle.tar                   check it against its manifest
   bundle install    cordon-bundle.tar                   verify, THEN extract
```

```
   VERIFY-BEFORE-EXTRACT
   ┌──────────────────────────────────────────────────────────────┐
   │ install = verify the manifest, then safe-extract (no path    │
   │ traversal, no symlink escape). A bundle that fails the check │
   │ is never unpacked.                                           │
   └──────────────────────────────────────────────────────────────┘
```

## Keeping intel current without a network

```
   internet host:   cordon-scanner advisories sync            (build the data)
        │           tar it up, carry it across the gap
        ▼
   air-gapped host: cordon-scanner scan . --advisories path/to/advisories/
```

Or use a signed advisory bundle (tutorial 09) so the secure side verifies an
Ed25519 signature before trusting a single byte.

## Determinism — the air-gap dividend

```
   same input  +  same rules  +  same advisory data   ─▶   byte-identical result
   no network  =  no "it changed between runs"          =  auditable, cacheable
```

Next: **[12 · Vetting a package before you install it](12-vetting-a-package.md)**.
