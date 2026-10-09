# 11 · Air-gapped installs

> **For Cordon 0.6.0.** Using another version? Open the tutorials at its tag: `https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` prints the link for the version you have installed.

Cordon never sends anything about the code it scans, which makes an air-gap the
easy case, not the hard one. Since 0.6.0 a default scan makes one kind of request:
it asks OSV (`osv-vulnerabilities.storage.googleapis.com`) which advisories changed
since its bundled database was built, with requests that are the same for everyone
and name no package. On an air-gapped runner that request cannot succeed, and the
scan would report its intel as stale (`OPERATIONAL.INTEL.STALE`). So set
`CORDON_OFFLINE=1` (or pass `--offline`) there: no request is attempted at all, and
intel is refreshed with the bundle installed below.

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
