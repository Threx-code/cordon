# 11 · Air-gapped installs

Cordon never sends anything about the code it scans, which makes an air-gap the
easy case, not the hard one. A normal scan pulls only Cordon's signed public intel
feed; set `CORDON_OFFLINE=1` (or pass `--offline`) on an air-gapped runner and it
makes no network attempt at all, using the intel bundle installed below.

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
