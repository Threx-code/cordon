# Configuring it

What to put in `.cordon.yaml`, which findings fail a build and which are
reported without failing one, how to turn the volume down without going
deaf, and what each exit code means.

The ordering matters and is the point of the first section: a repository
being scanned cannot weaken the gate an organisation set.

## Configure it

Cordon runs correctly with no configuration. Add `cordon.yaml` (or `.yml`,
`.cordon.yaml`, `.cordon.yml`) at the tree root; `--config PATH` points elsewhere.

```yaml
version: 1
scan:
  severity_threshold: low        # info | low | medium | high | critical
  confidence_threshold: low      # low | medium | high | confirmed
  exclude: ["vendor/**", "**/*.min.js"]
  include: []                    # empty means everything not excluded
  detectors: {secrets: true, capability: true}   # all on unless named
  minified: ["dist/**"]          # treated as generated, not hand-written
  offline: true                  # the default
  allow_plugins: false           # third-party detectors, off by default
  profile: balanced              # fast | balanced | thorough
  limits: {max_file_bytes: 10485760, total_timeout: 900}
policy:
  fail_on: [high, {category: malicious}]
  fail_on_incomplete: false
  min_confidence_to_fail: medium
  advisory_domains: [infrastructure, container, cicd]   # reported, not failed
evidence: masked                 # none | masked | hash_only
rules:
  packs: [cordon-builtin]
  extra: []                      # additional YAML rule packs
  disabled: []                   # rule ids that must not fire
suppressions:
  - rule: SUSPECT.DECODE_EXEC.001
    path: "src/loader.js"
    justification: "Reviewed by the platform team, tracked in TICKET-42."
    expires: 2026-11-07          # required, at most a year out
    approved_by: "platform-team"
```

Unknown keys are refused with a suggestion — a silently-ignored `sevrity_threshold`
would leave you believing a threshold is in force when the default is.

### The four layers

```
   ┌─────────────────────────────────────────────────────────────────┐
   │ 4  COMMAND LINE   highest precedence — still checked vs ceiling │  each layer
   │ 3  REPO CONFIG    the file above                                │  can only make
   │ 2  ORG POLICY     --policy / $CORDON_POLICY — a CEILING         │  a setting
   │ 1  BUILT-IN       safe with no config at all                    │  STRICTER
   └─────────────────────────────────────────────────────────────────┘

   A config discovered INSIDE the scanned tree is untrusted input: it cannot
   raise a limit or add a rule pack, and both attempts are reported. A --config
   file is operator input and keeps those powers.
```

### Suppressions

```
   one rule  +  one path  +  a justification  +  an expiry (≤ 1 year)
   wildcards refused. A suppressed finding STAYS in the report, marked — an
   auditor's first question is what the tool was told to ignore.
```

### Limits

| Limit | Default | Bounds |
|---|---|---|
| `max_file_bytes` | 10 MiB | Largest file read in full; beyond it a prefix is scanned and the scan is marked incomplete. |
| `max_line_bytes` | 1 MiB | Longest line considered. |
| `max_total_bytes` | 5 GiB | Total bytes traversed. |
| `max_files` | 200,000 | Files walked. |
| `max_findings` | 50,000 | Findings retained. |
| `max_dependencies` | 100,000 | Nodes in the dependency graph. |
| `per_file_timeout` | 5 s | Detector time on one file. |
| `total_timeout` | 900 s | Whole scan. |
| `max_archive_ratio` | 200 | Compression ratio before an archive is refused. |
| `max_archive_entries` | 50,000 | Members extracted. |
| `max_archive_depth` | 3 | Nested archive levels. |
| `max_uncompressed_bytes` | 2 GiB | Expanded archive size. |
| `max_path_depth` | 64 | Directory nesting. |
| `max_path_bytes` | 4096 | Path length. |
| `max_memory_bytes` | 1 GiB | File content held at once. |
| `max_workers` | 0 (automatic) | Worker processes. |

Reaching any limit produces a finding and marks the scan incomplete. **A scan
that stopped early and a scan that found nothing never look the same.**

---

## Tuning what fires

```
   THE NOISE LADDER — least blunt first, and EVERY rung is recorded in the output
   ┌────────────────────────────────────────────────────────────────────────────┐
   │ 1  raise the threshold   --severity medium   (cannot hide a failure)       │
   │ 2  exclude generated      exclude: ["dist/**","vendor/**"]                 │
   │ 3  disable a rule         rules.disabled: [SUSPECT.OBFUSCATION.…]          │
   │ 4  suppress one finding   one rule + one path + justification + expiry     │
   │ 5  disable a detector     scan.detectors: {obfuscation: false}  ← bluntest │
   └────────────────────────────────────────────────────────────────────────────┘
     A check turned off and a check that found nothing must not look the same.

   cordon-scanner rules show SUSPECT.DECODE_EXEC.001   # see what a rule does first
```

---

## What fails a build

```
   ┌───────────────────────────────┬───────────────────────────────────────┐
   │ FAILS THE BUILD               │ REPORTED, DOES NOT FAIL               │
   │ (this code is compromised or  │ (a posture choice the project made    │
   │  giving something away)       │  about its own infrastructure)        │
   ├───────────────────────────────┼───────────────────────────────────────┤
   │ malware, leaked credentials,  │ security group open to the internet,  │
   │ obfuscation, exfiltration,    │ privileged: true, a Dockerfile doing  │
   │ anything category: malicious  │ curl | sh                             │
   └───────────────────────────────┴───────────────────────────────────────┘
     the split is policy.advisory_domains — MEASURED: on 1,427 repos, failing on
     posture passes 76.2%; not failing on it passes 85.4% with FEWER findings,
     detection unchanged (same 1,301/1,497 malicious PyPI fail either way).
```

To fail on everything (pre-0.3 behaviour): `policy: {advisory_domains: []}`. A
`MALWARE.*` rule in one of those domains still fails — its category is the
stronger claim about the same file.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Clean. The scan completed and nothing met the failure policy. |
| 1 | Findings. Something met the failure policy. |
| 2 | Scanner error. Cordon itself failed — report it. |
| 3 | Configuration error. Fix the invocation or the config. |
| 4 | Incomplete, and `--fail-on-incomplete` was set. |

`if cordon-scanner scan .` is correct with no flags; any non-zero fails safe. A
pipeline that cannot tell "the scanner broke" from "your code is bad" gets
configured to ignore both.

---

## Adopting on an existing codebase

```
   turning a scanner on in a mature repo = a day-one backlog nobody can action.
   so: record it, gate on what's NEW.

   baseline create .            ─▶ cordon-baseline.json   (commit it, review it)
   scan . --baseline ….json     ─▶ existing debt marked, not failing
   baseline compare .           ─▶ fails only on new findings
```

Baselined findings stay in the report, marked — debt is visible, not deleted.
**Malicious findings are never baselined:** "we haven't fixed this yet" is not a
coherent position about evidence of intent to harm.

---
