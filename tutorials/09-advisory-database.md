# 09 · The advisory database

> **For Cordon 0.7.0.** Using another version? Open the tutorials at its tag: `https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` prints the link for the version you have installed.

The malicious/vulnerable-package lists (tutorial 03) ship *with* the tool. A scan reads
them locally, and by default first asks OSV for what changed since they were built: the same
requests for everyone, naming nothing you scan (`--offline` makes no request at all). Intel
older than a week without that refresh makes the scan incomplete. This is how you keep the
local data fresh.

```
   SCAN TIME                              REFRESH TIME (separate, deliberate)
   ─────────                              ──────────────────────────────────
   the local data, plus OSV's changes     cordon-scanner advisories sync
   since it was built (unless --offline)  cordon-scanner advisories sync --bundle <url|dir>
```

## Two ways to refresh

```
   A) BUILD FROM OSV                         B) INSTALL A SIGNED BUNDLE
   ─────────────────                         ──────────────────────────
   advisories sync                           advisories sync --bundle <url|dir>
        │                                          │
        ▼                                          ▼
   pull OSV's bulk export                     fetch a pre-built bundle, or read
                                              one carried in a folder (tutorial 40)
        │                                          │
        ▼                                     ┌────┴───────────────────────────┐
   rank + normalise per ecosystem             │ verify Ed25519 signature       │
        │                                     │ against the PINNED release key │
        ▼                                     │  BEFORE unpacking anything     │
   write local advisory data                 └────┬────────────────────────────┘
                                                  ▼
                                              extract → digest-check every file
```

Building from source reads OSV's per-ecosystem exports from
`osv-vulnerabilities.storage.googleapis.com` and, for RubyGems, the Ruby Advisory
Database (rubysec) from `codeload.github.com` -- the source `bundler-audit` and
Trivy use, which carries Ruby advisories OSV does not. An advisory both sources
carry is kept once. Nothing about the code you scan is sent to either.

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

`--advisories` replaces the database for one scan with a single JSON file: a list of records
in the shipped format (`ecosystem`, `name`, `versions` or `introduced`/`fixed`, `severity`,
`malicious`, `id`). An organisation's own list of banned releases works the same way:

```
   cordon-scanner scan .  --advisories org-advisories.json
```

```json
[{"id": "ACME-1", "ecosystem": "npm", "name": "left-pad", "versions": ["1.3.0"],
  "severity": "high", "summary": "banned by the security team", "malicious": false}]
```

For an air-gapped site, carry the signed bundle instead (tutorial 40).

```
   --only npm pypi        sync just these ecosystems
```

Next: **[10 · CI & git hooks](10-ci-and-hooks.md)**.
