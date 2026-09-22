# 15 · Vetting a package before you install it

The most common question anyone asks a supply-chain scanner: *should I install
this?* Cordon answers it without installing, without unpacking by hand, and
without running a line of what it reads.

```
┌──────────────────────────────────────────────────────────────────────────┐
│   npm pack lodash              ──▶  lodash-4.17.21.tgz                   │
│   pip download requests        ──▶  requests-2.32.3.tar.gz               │
│                                     requests-2.32.3-py3-none-any.whl     │
│                                                                          │
│   cordon-scanner scan lodash-4.17.21.tgz                                 │
│                                                                          │
│   An archive is walked in memory. Nothing is written to disk,            │
│   nothing is executed, and the install hooks inside it are read          │
│   as text -- which is the only safe way to read an install hook.         │
└──────────────────────────────────────────────────────────────────────────┘
```

## What an archive scan does

```
┌──────────────────────────────────────────────────────────────────────────┐
│   archive                                                                │
│     │                                                                    │
│     ├─ expand, bounded ....... member count, member size, total          │
│     │                          size, compression ratio, path depth.      │
│     │                          A zip bomb is refused, and the            │
│     │                          refusal is a finding, not a silence.      │
│     │                                                                    │
│     ├─ per-member checks ..... every file detector: secrets,             │
│     │                          obfuscation, capabilities, binaries       │
│     │                                                                    │
│     ├─ manifest hooks ........ package.json scripts, setup.py            │
│     │                          cmdclass -- what runs on install          │
│     │                                                                    │
│     └─ dependency graph ...... the lockfile inside the archive, so       │
│                                advisory, licence and integrity           │
│                                rules answer for the package too          │
└──────────────────────────────────────────────────────────────────────────┘
```

## The three questions, and the commands that answer them

### 1. Does it run anything when I install it?

```bash
cordon-scanner scan pkg.tgz -f json:out.json
jq '.findings[] | select(.rule_id | test("INSTALL|MALWARE")) |
    {rule_id, path: .location.path, message}' out.json
```

```
┌──────────────────────────────────────────────────────────────────────────┐
│   An install hook is not suspicious by itself -- native modules          │
│   build this way. What matters is what the hook DOES:                    │
│                                                                          │
│     postinstall: node-gyp rebuild        ordinary. A native build.       │
│     postinstall: node lib/postinstall.js ordinary until you read it.     │
│     postinstall: curl x | sh             a dropper.                      │
│     postinstall: node -e <base64 blob>   a dropper that is hiding.       │
│                                                                          │
│   Cordon follows the hook into the file it names, and then into          │
│   what that file imports, so the payload does not escape by being        │
│   one module away.                                                       │
└──────────────────────────────────────────────────────────────────────────┘
```

### 2. Is the release itself known-bad, or withdrawn?

```bash
# offline: 268,443 bundled advisories, malicious + high/critical
cordon-scanner scan pkg.tgz

# online: also ask the registry what it says right now
cordon-scanner scan pkg.tgz --online
```

```
┌──────────────────────────────────────────────────────────────────────────┐
│   OFFLINE answers                  ONLINE additionally answers           │
├──────────────────────────────────────────────────────────────────────────┤
│   is this name+version named       was this version YANKED or            │
│   by an advisory?                  unpublished since?                    │
│                                                                          │
│   is the name a typosquat of        is the lockfile hash the one         │
│   something popular?                the registry serves?                 │
│                                                                          │
│   does the lockfile pin hashes      is this pin far behind what          │
│   at all?                           is published now?                    │
│                                                                          │
│                                     did this release skip the            │
│                                     provenance its siblings have?        │
│                                                                          │
│   Online applies to npm and PyPI only, and every online finding          │
│   is marked as not reproducible offline.                                 │
└──────────────────────────────────────────────────────────────────────────┘
```

### 3. Was it built from the source it claims?

```bash
pip install 'cordon-scanner[attest]'
cordon-scanner scan pkg.tgz --online
```

```
┌──────────────────────────────────────────────────────────────────────────┐
│   A stolen publish token uploads a malicious build that still            │
│   names the honest repository. Reading the linked source proves          │
│   nothing -- the artefact and the repository are not connected by        │
│   anything except a claim.                                               │
│                                                                          │
│   Provenance connects them:                                              │
│                                                                          │
│     registry ──▶ sigstore bundle ──▶ Fulcio certificate                  │
│                                       └─ which workflow, which repo      │
│                                     ──▶ Rekor inclusion proof            │
│                                     ──▶ in-toto subject digest           │
│                                          └─ must equal YOUR pin          │
│                                                                          │
│     VULNERABLE.PROVENANCE.INVALID.001   signed, but not for this         │
│                                         artefact or not by that repo     │
│     POLICY.PROVENANCE.UNVERIFIED.001    nothing to check it against      │
│                                                                          │
│   See tutorial 05 for the full walkthrough.                              │
└──────────────────────────────────────────────────────────────────────────┘
```

## Reading the verdict

```
┌──────────────────────────────────────────────────────────────────────────┐
│   exit 0   nothing met the failure policy                                │
│   exit 1   something did -- read it before installing                    │
│   exit 4   the scan was DEGRADED and you asked to be told                │
│                                                                          │
│   Exit 4 is the one people skip. An archive that hit a size              │
│   ceiling, or a member that was refused, means part of the               │
│   package was never examined. `complete: false` says so, and             │
│   --fail-on-incomplete turns it into a non-zero exit:                    │
│                                                                          │
│     cordon-scanner scan pkg.tgz --fail-on-incomplete                     │
│                                                                          │
│   A refused member is not a clean member.                                │
└──────────────────────────────────────────────────────────────────────────┘
```

## Vetting a whole lockfile before an upgrade

```bash
# the graph you are about to install, checked against the registry
cordon-scanner scan . --online --timeout 120 -f json:before.json

# after `npm update` / `poetry update`
cordon-scanner scan . --online --timeout 120 -f json:after.json

# what changed
diff <(jq -r '.dependencies[].purl' before.json | sort) \
     <(jq -r '.dependencies[].purl' after.json  | sort)
```

```
┌──────────────────────────────────────────────────────────────────────────┐
│   --online is bounded, and says what it did not reach:                   │
│                                                                          │
│     200 queries per scan, direct dependencies first                      │
│     the scan's --timeout applies to the network phase too                │
│                                                                          │
│     OPERATIONAL.REGISTRY.NOT_ASKED.001                                   │
│         '50 of 250 package(s) were never asked about'                    │
│                                                                          │
│   and a scan that did not finish its online phase reports                │
│   complete: false rather than a clean answer.                            │
└──────────────────────────────────────────────────────────────────────────┘
```

---

Next: **[16 · The sandbox](16-the-sandbox.md)** -- for when reading is not enough.
