<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Threx-code/cordon/main/docs/assets/logo-dark.svg">
  <img src="https://raw.githubusercontent.com/Threx-code/cordon/main/docs/assets/logo-light.svg" alt="Cordon" width="260">
</picture>

# Cordon

[![CI](https://github.com/Threx-code/cordon/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Threx-code/cordon/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/cordon-scanner?logo=pypi&logoColor=white)](https://pypi.org/project/cordon-scanner/)
[![Python](https://img.shields.io/pypi/pyversions/cordon-scanner)](https://pypi.org/project/cordon-scanner/)
[![Runtime dependencies](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen)](https://github.com/Threx-code/cordon/blob/main/pyproject.toml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/Threx-code/cordon/blob/main/LICENSE)
[![Coverage matrix](https://img.shields.io/badge/rules-1%2C188-informational)](https://github.com/Threx-code/cordon/blob/main/docs/05-COVERAGE-MATRIX.md)
[![Ecosystems](https://img.shields.io/badge/ecosystems-17-informational)](https://github.com/Threx-code/cordon/blob/main/docs/07-ECOSYSTEMS.md)

A language-agnostic software **supply-chain security scanner**. It reads source,
manifests, lockfiles, build scripts, CI config, Dockerfiles and IaC — and reports
malicious packages, install-time behaviour, leaked credentials and dependency risk.

Seventeen package ecosystems, from npm and PyPI to Conan, Hex, CRAN and Bazel —
the file-by-file list, and which checks each one gets, is in
[docs/07-ECOSYSTEMS.md](https://github.com/Threx-code/cordon/blob/main/docs/07-ECOSYSTEMS.md).

```
   ┌─────────────────────────────────────────────────────────────────────────┐
   │  Cordon READS.  It never executes the code it scans, and never touches  │
   │  the network unless you pass --online.  Safe on hostile packages,       │
   │  safe in an air-gap, and its results are reproducible.                  │
   └─────────────────────────────────────────────────────────────────────────┘
```

```bash
pipx install cordon-scanner
cordon-scanner scan .
```

```
   scan .
     │  walk        identify            run every            sort, dedupe,
     │  the tree    the target          applicable check     score
     ▼     │            │                    │                   │
   repo ───┴──▶ languages/manifests ──▶ detectors ──▶ findings ──▶ report
   dir/file/archive     lockfiles/CI                              text·json·sarif·…
```

> **New here?** The
> [tutorials](https://github.com/Threx-code/cordon/tree/main/tutorials) are
> short, diagram-first walkthroughs — one per use case.

---

## What it looks like

A package whose `postinstall` posts the environment to a webhook and pipes a
download into a shell, and a workflow that sends a publish token to a remote host:

![Terminal output: seven critical findings in a compromised npm package](https://raw.githubusercontent.com/Threx-code/cordon/main/docs/assets/demo.svg)

Real output, rendered from a captured run. It is an SVG, not a GIF — text, so it
can be read in a diff before it is trusted. A tool that flags committed binaries
should not ship one to advertise itself. Regenerate with `python scripts/render_demo.py`.

```
  Map of this page
  ├─ Install ................ pipx · pip · Action · container
  ├─ Run it ................. what to scan, what to emit, what appears
  ├─ Configure it ........... the file, the four layers, limits
  ├─ Environments ........... local · pre-commit · CI · monorepo · air-gap · enterprise
  ├─ Tuning ................. the noise ladder, least-blunt first
  ├─ Adopting ............... baseline the debt, gate on the new
  ├─ Accuracy ............... measured, reproducible
  ├─ What fails a build ..... compromise fails; posture is reported
  ├─ Exit codes ............. 0 clean · 1 findings · 2 broke · 3 config · 4 incomplete
  └─ Why this exists ........ the attack, and the three invariants
```

---

## Install

| Method | Command | Use when |
|---|---|---|
| pipx | `pipx install cordon-scanner` | Local development. Isolated, on PATH. |
| pip | `pip install cordon-scanner` | Inside a virtualenv you already manage. |
| GitHub Action | `uses: Threx-code/cordon/action@<sha>` | GitHub Actions. |
| Container | `docker run --rm -v "$PWD:/scan" ghcr.io/threx-code/cordon:<version>` | A container-native pipeline. |

Python 3.11 / 3.12 / 3.13 on Linux, macOS and Windows.

```
   OPTIONAL EXTRAS — opt-in, and each degrades to a STATED limit, never a crash
   ┌────────────────────────────────────────────────────────────────────────┐
   │  base           zero third-party runtime deps                          │
   │  [ast-js]       tree-sitter → JS/TS semantic rules   (tutorial 13)     │
   │  [attest]       sigstore    → provenance verification (tutorial 05)    │
   └────────────────────────────────────────────────────────────────────────┘
```

```
   PIN BY DIGEST, NOT BY TAG
   Action  → @<commit sha>     a tag is mutable; pinning to something the author
   Image   → @sha256:<digest>  can move defeats the point of running a scanner.
```

The Action and image are built from the distroless, non-root `Dockerfile` here,
signed keylessly with `cosign`, and carry SLSA build provenance — the same
controls the wheel and sdist get.

```bash
cordon --version
cordon-scanner rules list      # what will run
```

---

## Run it

```bash
cordon-scanner scan .                                  # a directory
cordon-scanner scan ./package.tgz                      # an archive, read in memory
cordon-scanner scan . --severity high --fail-on high   # gate a pipeline
```

### What gets scanned

```
   --exclude 'vendor/**'      skip paths (repeatable)
   --include 'src/**'         restrict to paths
   --tracked                  only files git tracks
   --git-diff origin/main     only what changed vs a ref
   --staged                   the git INDEX, not the working tree

   WHY --staged for a pre-commit hook
   ┌──────────────────────────────────────────────────────────────────┐
   │ a hook reading the WORKING TREE is defeated by: stage a poisoned │
   │ file → restore the clean one. The poisoned blob commits; the     │
   │ clean one is scanned. Reading the index closes that.             │
   └──────────────────────────────────────────────────────────────────┘

   Narrowing applies to FILE analysis only. Dependency & manifest checks always
   run against the whole tree — a malicious transitive dep appears in no diff.
```

### What it emits

```
   -f text                 humans at a terminal (default)
   -f json                 machine-readable
   -f sarif:cordon.sarif   code-scanning platforms
   -f junit:results.xml    CI test reporters
   -f markdown             PR comments, job summaries
   -f github               inline annotations on a diff

   -f is repeatable; FMT:PATH writes to a file, bare FMT goes to stdout:
   cordon-scanner scan . -f github -f sarif:cordon.sarif -f json:result.json
```

### What appears in the report

```
   --evidence masked      (default) matched values are masked
   --evidence hash_only   no snippets — for a widely-readable report (PR, upload)
   Secret findings are hash-only regardless.  --reachability annotates CVE noise
   (tutorial 04).  --online adds live registry + provenance checks (tutorial 05).
```

### Other commands

```
   inventory .            what is this repo, and the evidence
   rules list|show|test   what can fire · one rule · run every rule's samples
   config explain         effective settings + which layer supplied each
   guard install|verify   fail-closed git hooks (tutorial 10)
   baseline create|compare adopt incrementally (tutorial 14)
   advisories sync        refresh the intel (tutorial 09)
   bundle create|install  air-gapped install (tutorial 11)
   sbom generate          CycloneDX / SPDX from the resolved graph
```

---

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

## Environments

```
   LOCAL          cordon-scanner scan .
                  incremental cache in $XDG_CACHE_HOME/cordon (authenticated;
                  a foreign entry is ignored). --cache-dir moves it.

   PRE-COMMIT     cordon-scanner guard install     # fail-closed shims in .git/hooks
                  guard verify                      # check they're intact
                  hooks live in .git/hooks (untracked): no commit/switch/clean
                  removes them, and if cordon can't run, the commit is refused.
```

Or the `pre-commit` framework — pinned to a release tag:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/Threx-code/cordon
    rev: v0.4.0
    hooks:
      - id: cordon
```

```
   GITHUB ACTIONS
   - uses: Threx-code/cordon/action@<sha>     # pin by commit, not tag
     with: {target: ., severity: medium, fail-on: high, sarif: true}

   inputs pass through the ENV, never interpolated into a shell. The action
   refuses to run under pull_request_target (writable token + secrets on a job
   that may check out untrusted code).
```

Or call the CLI directly — note `if: always()`, or uploading only on success
hides findings exactly when there are some:

```yaml
- run: pipx install cordon-scanner
- run: cordon-scanner scan . -f github -f sarif:cordon.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: {sarif_file: cordon.sarif}
```

```
   GITLAB · JENKINS · AZURE   templates in ci/ — all reduce to two lines:
     pip install cordon-scanner
     cordon-scanner scan . --fail-on high -f junit:cordon-junit.xml

   MONOREPO      cordon-scanner scan . --tracked --jobs 8 --exclude 'third_party/**'
                 cordon-scanner scan . --git-diff origin/main     # pull requests
                 exclude generated trees rather than lowering a limit — an
                 exclusion is visible; a lowered limit is a coverage loss.

   AIR-GAP       offline by default, no runtime deps. Nothing need be reachable.
                 --advisories ./advisories.json    to bring your own intel
                 see tutorial 11 for the signed offline bundle
```

Templates live in [`ci/`](https://github.com/Threx-code/cordon/tree/main/ci).
The advisory database ships inside the wheel (malicious entries + high/critical
vulns, to bound size); `cordon-scanner advisories sync` fetches the full,
unfiltered set into a local cache a scan then prefers — still no network at scan
time, only at the moment you ask for a refresh. A supplied `--advisories` file
*replaces* the bundled one rather than merging, so what you act on is what you chose.

```
   DYNAMIC ANALYSIS is a SEPARATE binary — on purpose, so nothing in a scan can
   ever execute what it scans:
     cordon-sandbox pypi suspicious-package --sandbox --fail-on high
```

### Enterprise — an organisation ceiling

```yaml
# org-policy.yaml   (point at it with --policy or $CORDON_POLICY)
version: 1
name: "acme-baseline"
enforce:
  min_severity_threshold: low       # repositories may not report less
  min_confidence_threshold: low
  detectors_required: [capability, manifest, secrets]
  allow_limit_increase: false
  allow_plugins: false
  allow_extra_rule_packs: false
  allow_network: false
  max_total_timeout: 600
policy: {fail_on: [high, {category: malicious}], fail_on_incomplete: true}
suppressions:
  max_duration_days: 90
  require_justification: true
  require_approver: true
  forbid_path_only: true
  forbid_categories: [malicious]
```

A repository config that conflicts with the ceiling is **refused, with the
conflict named** — not silently clamped. Command-line flags are checked against
the same ceiling.

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

## Accuracy, measured

Every number is measured against real code and re-run for the release. The
noise corpus and its driver ship here (`scripts/measure_noise.py`, over the
repository list in `scripts/data/measurement-corpus.json`), so anyone can
reproduce that row. The two malicious corpora are public datasets rather than
files in this repository: the methodology is in
[docs/05-COVERAGE-MATRIX.md](https://github.com/Threx-code/cordon/blob/main/docs/05-COVERAGE-MATRIX.md), and no driver for
them ships here.

| corpus | size | result |
|---|---|---|
| Widely used open-source repositories | **1,427** | 85.4% pass the default gate |
| Reference infrastructure, as its vendors publish it | **13 repos, 20,310 files** | 2,575 findings, 796 blocking |
| Real malicious PyPI packages | **1,497** | 86.9% detected, 86.9% fail the gate |
| Real malicious npm packages | **999** | 79.8% detected; 91.0% of those carrying a payload |

```
   NOISE     1,427 maintained projects (incl. security tools — a security tool's
             own signature file is the canonical false positive). 1,218 pass the
             default gate. Both MALWARE.* findings across the corpus are correct.
   IAC       the infrastructure the vendors themselves publish as correct — the
             Terraform modules AWS, Azure and Google ship, AWS's CloudFormation
             library, Kubernetes' own examples, Microsoft's Bicep registry and
             quickstart templates. Read by hand, five rules were wrong and each
             was fixed: 2,722 findings became 2,575 and 837 blocking became 796.
             What blocks now is 345 Azure rules opening SSH or RDP to the whole
             internet (Azure's demo templates really do that) and 320 CVEs in
             those repositories' own dependencies.
   RECALL    1,497 PyPI + 999 npm real malicious packages, extracted WITHOUT
             executing, scanned, deleted. ~⅛ of the npm set is payload-free
             metadata; of those with a payload, 91.0% are caught.
   READ      every rule class firing across >10 repositories was read by hand —
             a rule wrong across 40 unrelated projects is wrong whatever one case looks like.
   SUITE     10,000+ tests every push · Linux/macOS/Windows · Py 3.11/3.12/3.13 ·
             fuzzing · latency budgets · reproducibility · Cordon scanning itself.
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

## Using it as a library

```python
from cordon_scanner import Scanner

scanner = Scanner.for_target("./repository")
result = scanner.scan("./repository")

for finding in result.findings:
    print(finding.rule_id, finding.severity, finding.location)
```

`Scanner.for_target` assembles configuration through the same resolver the CLI
uses, so the organisation ceiling applies. Everything returned is immutable and
output is deterministic: identical inputs produce identical findings in a stable order.

---

## Why this exists

```
   SAST / linters / CVE DBs  answer:  "does the code I WROTE contain a bug?"
   Cordon                    answers:  "is the code I did NOT write attacking me?"
```

A typical app is a few thousand lines of first-party code on top of a few
**hundred thousand** lines of third-party code — resolved transitively and run on
the developer's machine at **install time**, before any test, review or container.

```
   THE ATTACK, ON REPEAT
   gain publish rights ──▶ publish a version identical to the last ──▶ + a
   (phished account,        plus one lifecycle script                  lifecycle
    expired domain,         (postinstall, prepare, build.rs,           hook runs
    typosquat, handed-off   setup.py, a Gradle task)                   as YOU
    package)                                                             │
        the script reads SSH keys / cloud creds / publish tokens ◀───────┘
        and sends them out — then uses them to poison every package you maintain.

   All of it between typing `install` and getting a prompt back. No review, no
   CI gate, no sandbox. This is event-stream, ua-parser-js, coa, rc, node-ipc,
   the torchtriton dependency-confusion, the xz-utils backdoor, the 2025 npm worms.
```

Three properties follow, and shape everything:

```
   ┌─────────────────────────────────────────────────────────────────────────┐
   │ 1  THE TARGET IS UNTRUSTED INPUT, config file included. A repo cannot   │
   │    use its own config to blind the scan without the output saying so.   │
   │ 2  NOTHING FROM THE TARGET IS EXECUTED. Lockfiles are parsed, never     │
   │    resolved. No package manager is invoked.                             │
   │ 3  REDUCED COVERAGE IS ALWAYS REPORTED. A limit hit, a detector off, a  │
   │    file excluded, a rule disabled — each is a finding. Examined-nothing │
   │    must never look like found-nothing.                                  │
   └─────────────────────────────────────────────────────────────────────────┘
```

### The guarantee, stated precisely

Cordon is a static analyser; static analysis cannot decide what a program does
at runtime. So the promise is deliberately narrow:

> **No evasion is silent.** A technique used to hide behaviour is either resolved
> to the real behaviour, or produces a signal of its own.

```
   RESOLVED (each has a test)          →  the real callee
   ─────────────────────────
   rename an import, bind to a local, split a token across a concat,
   compute a name at runtime, encode in layers, write shell inside another lang
                                       │
   what CANNOT be resolved ────────────┴──▶ becomes its OWN finding
                                            (a runtime-assembled target = dynamic dispatch)

   what remains = behaviour that exists only when the code RUNS (a payload
   decoded from a network response). No static tool sees that; this one does not
   pretend to — that is the separate, opt-in sandbox.
```

Detection is strongest where a language pack defines the capability primitives; a
language with no pack inherits no behavioural rules (the coverage matrix says
which). Registry-answered checks (withdrawal, published-hash) need `--online`.

---

## Documentation

| Document | Contents |
|---|---|
| [tutorials/](https://github.com/Threx-code/cordon/tree/main/tutorials) | Diagram-first walkthroughs, one per use case: scan, detection, reachability, provenance, CI, air-gap |
| [docs/01-ARCHITECTURE.md](https://github.com/Threx-code/cordon/blob/main/docs/01-ARCHITECTURE.md) | Components, detection engine, rule format, extension points |
| [docs/02-THREAT-MODEL.md](https://github.com/Threx-code/cordon/blob/main/docs/02-THREAT-MODEL.md) | Attacker profiles, trust boundaries, the constraints they imply |
| [docs/03-INTERFACES.md](https://github.com/Threx-code/cordon/blob/main/docs/03-INTERFACES.md) | CLI, configuration and SDK reference; SARIF mapping |
| [docs/04-OPERATIONS.md](https://github.com/Threx-code/cordon/blob/main/docs/04-OPERATIONS.md) | Deployment, rule authoring, performance, release process |
| [docs/05-COVERAGE-MATRIX.md](https://github.com/Threx-code/cordon/blob/main/docs/05-COVERAGE-MATRIX.md) | Every rule that ships, by threat domain and attack category |
| [docs/06-SANDBOX.md](https://github.com/Threx-code/cordon/blob/main/docs/06-SANDBOX.md) | The opt-in component that runs a package in isolation, and what it observes |
| [docs/07-ECOSYSTEMS.md](https://github.com/Threx-code/cordon/blob/main/docs/07-ECOSYSTEMS.md) | Every ecosystem read, the files read for each, and which checks it gets |
| [docs/assets/](https://github.com/Threx-code/cordon/tree/main/docs/assets) | The logo, as SVG: wordmark (light and dark), mark, and a filled square for an avatar |

---

## Status

Beta, and the classifier says so. The detection engine, rule packs, seventeen
ecosystems, reporters, policy layer, baselines, git-aware scanning and the
advisory layer are implemented and tested; `docs/03-INTERFACES.md` separates the
commands that ship from those that are designed. Interfaces may still change
before 1.0, the bundled advisory set is the malicious plus high/critical subset
of OSV rather than all of it, four of the seventeen ecosystems have no advisory
feed to match against at all, and reachability is modelled at its import tier
rather than its call-graph tier — none of it hidden: `cordon-scanner rules list`
shows what runs, `docs/07-ECOSYSTEMS.md` shows which checks each ecosystem gets,
and every reduction in coverage is reported as a finding rather than left for a
reader to infer.

## Licence

Apache-2.0. See [LICENSE](https://github.com/Threx-code/cordon/blob/main/LICENSE) and [NOTICE](https://github.com/Threx-code/cordon/blob/main/NOTICE).
