# 06 · The advisory database

The malicious/vulnerable-package lists (tutorial 03) ship *with* the tool and are
used offline at scan time. This is how you keep them fresh.

```
   SCAN TIME                         REFRESH TIME (separate, deliberate)
   ─────────                         ──────────────────────────────────
   read the bundled data, offline    cordon-scanner advisories sync
   no network, reproducible          cordon-scanner advisories sync --bundle <url>
```

## Two ways to refresh

```
   A) BUILD FROM OSV                         B) INSTALL A SIGNED BUNDLE
   ─────────────────                         ──────────────────────────
   advisories sync                           advisories sync --bundle <url>
        │                                          │
        ▼                                          ▼
   pull OSV's bulk export                     download a pre-built bundle
        │                                          │
        ▼                                     ┌────┴───────────────────────────┐
   rank + normalise per ecosystem            │ verify Ed25519 signature        │
        │                                     │ against the PINNED release key │
        ▼                                     │  BEFORE unpacking anything     │
   write local advisory data                 └────┬────────────────────────────┘
                                                   ▼
                                              extract → digest-check every file
```

## Why the signature comes first

```
   A vulnerability database is a high-value target: water it down and every scan
   that trusts it goes quiet. So the bundle is signed, and the signature is checked
   BEFORE a single byte is unpacked — with a verify-only Ed25519 that is vendored
   into the tool, so refreshing needs no third-party crypto dependency.

        download ─▶ VERIFY SIG ─▶ safe-extract ─▶ per-file digest ─▶ install
                       │
                    fail here  ─▶ nothing is unpacked, old data untouched
```

## Point a scan at your own data

```
   cordon-scanner scan .  --advisories path/to/advisories/     # air-gapped sites
```

```
   --only npm pypi        sync just these ecosystems
```

Next: **07 — CI & git hooks**.
