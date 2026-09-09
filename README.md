# Cordon

A language-agnostic software supply-chain security scanner. It reads source,
dependency manifests, lockfiles, build scripts, CI configuration, Dockerfiles
and infrastructure-as-code, and reports malicious packages, install-time
behaviour, leaked credentials and dependency risk.

No runtime dependencies. No network access unless you ask for it. It never
executes the code it scans.

```bash
pipx install cordon-scanner
cordon-scanner scan .
```

- [Install](#install)
- [Run it](#run-it)
- [Configure it](#configure-it)
- [Environments](#environments) — local, pre-commit, CI, monorepo, air-gapped, enterprise
- [Tuning what fires](#tuning-what-fires)
- [Adopting on an existing codebase](#adopting-on-an-existing-codebase)
- [Exit codes](#exit-codes)
- [Why this exists](#why-this-exists)

---

## Install

| Method | Command | Use when |
|---|---|---|
| pipx | `pipx install cordon-scanner` | Local development. Isolated, on PATH. |
| pip | `pip install cordon-scanner` | Inside a virtualenv you already manage. |
| GitHub Action | `uses: Threx-code/cordon@<sha>` | GitHub Actions. See [Environments](#environments). |

Python 3.11, 3.12 and 3.13 on Linux, macOS and Windows.

The Action is pinned by commit SHA rather than by a `@v0` tag: a tag is mutable,
and pinning the scanner by something its author can move defeats the point of
running it. There is no published container image yet -- that is Phase 6, along
with signed artefacts and provenance.

Verify the install:

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

### Choosing what gets scanned

```bash
cordon-scanner scan . --exclude 'vendor/**' --exclude 'dist/**'
cordon-scanner scan . --include 'src/**'
cordon-scanner scan . --tracked                # only files git tracks
cordon-scanner scan . --git-diff origin/main   # only what changed
cordon-scanner scan . --staged                 # the git index, not the working tree
```

`--staged` reads blobs from the git index rather than from disk. That matters
for a pre-commit hook: a hook reading the working tree is defeated by staging a
poisoned file and restoring the clean one, so the poisoned blob is what gets
committed and the clean one is what gets scanned.

Narrowing applies only to file analysis. Dependency and manifest checks always
run against the whole tree, because a malicious transitive dependency appears in
no diff.

### Output

```bash
cordon-scanner scan . -f text                       # default, for a terminal
cordon-scanner scan . -f json                       # machine-readable
cordon-scanner scan . -f sarif:cordon.sarif         # code scanning platforms
cordon-scanner scan . -f junit:results.xml          # CI test reporters
cordon-scanner scan . -f markdown                   # PR comments, job summaries
cordon-scanner scan . -f github                     # inline annotations on a diff

cordon-scanner scan . -f github -f sarif:cordon.sarif -f json:result.json
```

`--format` is repeatable, and `FMT:PATH` writes that format to that file. Only
formats without a path go to stdout.

### Controlling what appears in the report

```bash
cordon-scanner scan . --evidence masked      # default: values are masked
cordon-scanner scan . --evidence hash_only   # no snippets at all
```

Use `hash_only` when the report goes somewhere widely readable — a pull-request
comment, a SARIF upload to a third-party platform. Secret findings are hash-only
regardless of this setting.

### Other commands

```bash
cordon-scanner inventory .                  # what is this repository, and the evidence
cordon-scanner rules list                   # every rule that can fire
cordon-scanner rules show RULE.ID           # one rule in full
cordon-scanner rules test                   # run every rule's own samples
cordon-scanner config validate              # check a configuration file
cordon-scanner config explain               # effective settings and where each came from
cordon-scanner guard install                # install fail-closed git hooks
cordon-scanner guard verify                 # check the hooks are intact
cordon-scanner baseline create              # record today's findings as known
cordon-scanner baseline compare             # fail only on what is new
```

`cordon-scanner config explain` is the one to reach for when a setting is not doing what
you expect: it prints the effective value of everything and names the layer that
supplied it.

---

## Configure it

Cordon runs correctly with no configuration. Add a file when you need to change
something.

Place any of `cordon.yaml`, `cordon.yml`, `.cordon.yaml` or `.cordon.yml` at the
root of the scanned tree. It is discovered automatically; `--config PATH` points
at one elsewhere.

```yaml
version: 1

scan:
  severity_threshold: low        # info | low | medium | high | critical
  confidence_threshold: low      # low | medium | high | confirmed

  exclude:
    - "vendor/**"
    - "**/*.min.js"
  include: []                    # empty means everything not excluded

  detectors:                     # every detector is on unless named here
    secrets: true
    capability: true

  minified:                      # treated as generated, not hand-written
    - "dist/**"

  offline: true                  # no network access. The default.
  allow_plugins: false           # third-party detectors. Off by default.
  profile: balanced              # fast | balanced | thorough

  limits:
    max_file_bytes: 10485760
    total_timeout: 900

policy:
  fail_on: [high, {category: malicious}]
  fail_on_incomplete: false
  min_confidence_to_fail: medium

evidence: masked                 # none | masked | hash_only

rules:
  packs: [cordon-builtin]
  extra: []                      # additional YAML rule packs
  disabled: []                   # rule ids that must not fire

suppressions:
  - rule: SUSPECT.DECODE_EXEC.001
    path: "src/loader.js"
    justification: "Reviewed by the platform team, tracked in TICKET-42."
    expires: 2026-11-07       # required, and at most a year out
    approved_by: "platform-team"
```

Unknown keys are refused, with a suggestion. A misspelled `sevrity_threshold`
that was silently ignored would leave you believing a threshold is in force when
the default is.

### Configuration layers

Four layers, applied in this order, each able to make a setting stricter:

1. **Built-in defaults** — safe with no configuration at all.
2. **Organisation policy** — `--policy` or `$CORDON_POLICY`. A ceiling, not a
   set of defaults.
3. **Repository configuration** — the file above.
4. **Command line** — highest precedence, still checked against the ceiling.

A configuration file discovered *inside the scanned tree* is treated as
untrusted input, because it is part of what you are scanning. It cannot raise a
resource limit, and it cannot add a rule pack. Both are reported rather than
silently ignored. A file named with `--config` is operator input and keeps those
powers.

### Suppressions

Every suppression names one rule **and** one path, carries a justification, and
expires. Wildcards in either field are refused, and the maximum lifetime is one
year. These are the tool's own requirements and apply whether or not an
organisation policy is configured.

A suppressed finding stays in the report, marked, with its justification
attached. An auditor's first question is what the tool was told to ignore.

### Limits

| Limit | Default | What it bounds |
|---|---|---|
| `max_file_bytes` | 10 MiB | Largest file read in full. Beyond it, a prefix is scanned and the scan is marked incomplete. |
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
| `mmap_threshold` | 1 MiB | Unused; retained for compatibility. |

Reaching any limit produces a finding and marks the scan incomplete. A scan that
stopped early and a scan that found nothing never look the same.

---

## Environments

### Local development

```bash
cordon-scanner scan .
```

The incremental cache makes repeat scans fast. It lives in
`$XDG_CACHE_HOME/cordon` or `~/.cache/cordon`, and `--cache-dir` moves it.
Entries are authenticated, so an entry written by anything else is ignored.

### Pre-commit hooks

Two options. Cordon's own, which fails closed:

```bash
cordon-scanner guard install     # writes shims into .git/hooks
cordon-scanner guard verify      # check they are still intact
```

The shims live in `.git/hooks`, which git does not track, so no commit, branch
switch, merge or `git clean` removes them. If cordon cannot run, the commit is
refused rather than allowed.

Or the `pre-commit` framework:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/Threx-code/cordon
    rev: v0.1.0
    hooks:
      - id: cordon
```

Either way the hook scans the git index, not the working tree.

### GitHub Actions

```yaml
- uses: Threx-code/cordon@<sha>   # pin by commit, not by tag
  with:
    target: .
    severity: medium
    fail-on: high
    sarif: true
```

Every input is passed through the environment rather than interpolated into a
shell command. The action refuses to run under `pull_request_target`, which
grants a writable token and repository secrets to a job that may check out
untrusted code.

Or call the CLI directly:

```yaml
- run: pipx install cordon-scanner
- run: cordon-scanner scan . -f github -f sarif:cordon.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: cordon.sarif
```

`if: always()` matters: uploading only on success hides findings exactly when
there are some.

### GitLab, Jenkins, Azure Pipelines

Templates are in [`ci/`](https://github.com/Threx-code/cordon/tree/main/ci). All of them reduce to the same two lines:

```bash
pip install cordon-scanner
cordon-scanner scan . --fail-on high -f junit:cordon-junit.xml
```

### Large repositories and monorepos

```bash
cordon-scanner scan . --tracked --jobs 8 --exclude 'third_party/**'
cordon-scanner scan . --git-diff origin/main       # pull requests
```

`--tracked` skips build output and anything git ignores. On a pull request,
`--git-diff` narrows file analysis to what changed while still checking the whole
dependency graph.

If scans are slow, exclude generated trees rather than lowering a limit.
Exclusions are visible in the report; a lowered limit is a coverage loss that
looks like tuning, and is reported as one.

### Air-gapped and offline

Cordon is offline by default and has no runtime dependencies. Nothing needs to
be reachable.

The advisory database ships inside the wheel, so known-malicious package
versions are matched without a network call. To use your own -- an OSV export,
or an internal list -- pass it in:

```bash
cordon-scanner scan . --advisories ./advisories.json
```

The format is a JSON list, so an export script needs no library:

```json
[
  {"ecosystem": "npm", "name": "event-stream", "versions": ["3.3.6"],
   "malicious": true, "summary": "...", "reference": "https://...", "id": "GHSA-..."}
]
```

A supplied database replaces the bundled one rather than adding to it: if you
are stating what your organisation acts on, silently merging a shipped list into
it would produce findings you did not choose.

```bash
pip download cordon-scanner -d ./wheels     # on a connected machine
pip install --no-index --find-links ./wheels cordon-scanner
cordon-scanner scan . --offline
```

Rule packs ship inside the wheel. Nothing is fetched at scan time.

### Enterprise, with an organisation policy

A policy file is a ceiling. Distribute it however you distribute configuration,
and point at it with `--policy` or `$CORDON_POLICY`.

```yaml
# org-policy.yaml
version: 1
name: "acme-baseline"
issuer: "security@acme.example"
issued: 2026-01-01

enforce:
  min_severity_threshold: low       # repositories may not report less
  min_confidence_threshold: low
  detectors_required: [capability, manifest, secrets]
  allow_limit_increase: false
  allow_plugins: false
  allow_extra_rule_packs: false
  allow_network: false
  max_total_timeout: 600

policy:
  fail_on: [high, {category: malicious}]
  fail_on_incomplete: true

suppressions:
  max_duration_days: 90
  require_justification: true
  require_approver: true
  forbid_path_only: true
  forbid_categories: [malicious]
```

A repository whose configuration conflicts with the ceiling is refused, with the
conflict named — not silently clamped, which would leave the repository owner
believing a setting is in force when it is not. Command-line flags are checked
against the same ceiling.

---

## Tuning what fires

Too much noise, in order of preference:

1. **Raise the reporting threshold.** `--severity medium` hides low-value
   findings. It cannot hide anything that fails the build; a report that omits
   the reason for a non-zero exit is worse than a noisy one.
2. **Exclude generated trees.** `exclude: ["dist/**", "vendor/**"]`.
3. **Disable a rule.** `rules.disabled: [SUSPECT.OBFUSCATION.LONGLINE.001]`.
   Reported, so the reduction is visible.
4. **Suppress a specific finding.** One rule, one path, a justification and an
   expiry.
5. **Disable a detector.** `scan.detectors: {obfuscation: false}`. The bluntest
   instrument; reported as a coverage loss.

Every one of these is recorded in the output. A check that was turned off and a
check that found nothing must not look the same.

To see what a rule actually does before deciding:

```bash
cordon-scanner rules show SUSPECT.DECODE_EXEC.001
```

---

## Adopting on an existing codebase

Turning a scanner on in a mature repository usually produces a backlog nobody
can act on that day. Record it and gate on what is new:

```bash
cordon-scanner baseline create .                          # writes cordon-baseline.json
git add cordon-baseline.json && git commit -m "Record cordon-scanner baseline"

cordon-scanner scan . --baseline cordon-baseline.json     # existing debt is marked
cordon-scanner baseline compare .                         # fails only on new findings
```

Baselined findings stay in the report, marked, so the debt is visible rather
than deleted. Malicious findings are never baselined: "we have not fixed this
yet" is not a coherent position about evidence of intent to harm.

Review the file before committing it. Every entry is something the repository is
choosing not to fix yet.

---

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Clean. The scan completed and nothing met the failure policy. |
| 1 | Findings. The scan completed and something met the failure policy. |
| 2 | Scanner error. Cordon itself failed — report it. |
| 3 | Configuration error. Fix the invocation or the config file. |
| 4 | Incomplete, and `--fail-on-incomplete` was set. |

`if cordon-scanner scan .` is correct with no flags, and any non-zero code fails safe.
The distinctions matter because a pipeline that cannot tell "the scanner broke"
from "your code is bad" gets configured to ignore both.

---

## Using it as a library

```python
from cordon_scanner import Scanner

scanner = Scanner.for_target("./repository")
result = scanner.scan("./repository")

for finding in result.findings:
    print(finding.rule_id, finding.severity, finding.location)
```

`Scanner.for_target` assembles the configuration through the same resolver the
CLI uses, so the organisation ceiling applies. Constructing `Scanner(config)`
directly is supported for a config you built deliberately; it does not clamp,
because it cannot know where the config came from.

Everything returned is immutable, and output is deterministic: identical inputs
produce identical findings in a stable order.

---

## Why this exists

Most scanning answers *"does the code I wrote contain a bug?"* — well served by
SAST tools, linters and CVE databases.

Cordon answers *"is the code I did not write trying to attack me?"*

A typical application is a few thousand lines of first-party code on top of a
few hundred thousand lines of third-party code, pulled from a public registry,
resolved transitively, and executed on the developer's machine at install time —
before any test runs, any review happens, or any container boundary exists.

The attack pattern repeats with small variations. Someone gains publish rights
to a package, through a phished maintainer account, an expired domain, an
abandoned package handed to a volunteer, or a typosquatted name nobody watched.
They publish a version functionally identical to the last one, plus a lifecycle
script — `postinstall`, `prepare`, a `build.rs`, a `setup.py` command class, a
Gradle task. That script runs as the developer, with the developer's SSH keys,
cloud credentials and publish tokens. It reads what it can reach and sends it
somewhere, and increasingly uses what it stole to publish poisoned versions of
every package that developer maintains.

The whole exchange happens between typing an install command and getting a
prompt back. There is no review step, no CI gate, no sandbox.

This is the documented shape of `event-stream`, `ua-parser-js`, `coa`, `rc`,
`node-ipc`, the `torchtriton` dependency-confusion incident, the `xz-utils`
backdoor, and the self-replicating npm worms of 2025.

Three properties follow from that, and they shape everything else:

- **The scan target is untrusted input**, including its configuration file. A
  repository cannot use its own config to blind the scan without the output
  saying so.
- **Nothing from the target is ever executed.** Lockfiles are parsed, never
  resolved. No package manager is invoked.
- **Reduced coverage is always reported.** A limit reached, a detector disabled,
  a file excluded, a rule turned off — each produces a finding. A scan that
  examined nothing must never look like a scan that found nothing.

### What it does not claim

Cordon is a static analyser. It reads code and configuration; it does not run
them, and static analysis cannot decide what a program will do at runtime. So
the guarantee is deliberately narrower than "it catches attacks", and worth
stating precisely:

> No evasion is silent. A technique used to hide behaviour is either resolved to
> the real behaviour, or produces a signal of its own.

Renaming an import, binding a function to a local name, splitting a token or a
primitive across a concatenation, computing a name at runtime, encoding a
payload in several layers, writing a shell command inside another language — all
of these are resolved, and each has a test that proves it. What cannot be
resolved becomes its own finding: a target assembled at runtime is reported as
dynamic dispatch, because reaching for a name that cannot be read is itself
informative.

What remains is behaviour that exists only when the code runs — a target decoded
from a network response, logic gated on a value that is fetched. No static tool
observes that, and this one does not pretend to. Observing it requires running
the code in isolation, which is a separate opt-in component precisely because
"never executes the code it scans" is a promise worth keeping in the default
tool.

Two further limits are worth knowing. Detection is strongest where a language
pack defines the capability primitives, and a language with no pack inherits no
behavioural rules — the coverage matrix in `docs/05-COVERAGE-MATRIX.md` says
which is which. And checks that need a registry to answer them (whether a
version was withdrawn, whether a hash matches what is published) require
`--online`, and are absent by default.

---

## Documentation

| Document | Contents |
|---|---|
| [docs/01-ARCHITECTURE.md](https://github.com/Threx-code/cordon/blob/main/docs/01-ARCHITECTURE.md) | Components, detection engine, rule format, extension points |
| [docs/02-THREAT-MODEL.md](https://github.com/Threx-code/cordon/blob/main/docs/02-THREAT-MODEL.md) | Attacker profiles, trust boundaries, the constraints they imply |
| [docs/03-INTERFACES.md](https://github.com/Threx-code/cordon/blob/main/docs/03-INTERFACES.md) | CLI, configuration and SDK reference; SARIF mapping |
| [docs/04-OPERATIONS.md](https://github.com/Threx-code/cordon/blob/main/docs/04-OPERATIONS.md) | Deployment, rule authoring, performance, release process |

---

## Status

Alpha, and the classifier says so. The detection engine, rule packs, eleven
ecosystems, reporters, policy layer, baselines, git-aware scanning and the
advisory layer are implemented and tested; `docs/03-INTERFACES.md` separates the
commands that ship from those that are designed.

What alpha means here in practice: the interfaces may still change, the bundled
advisory set covers documented incidents rather than a full feed, and the benign
corpus behind the `confidence: high` measurement is small. None of those is
hidden -- `cordon-scanner rules list` shows what will run, `rules diff` shows what
changed, and every reduction in coverage is reported as a finding.

## Licence

Apache-2.0. See [LICENSE](https://github.com/Threx-code/cordon/blob/main/LICENSE) and [NOTICE](https://github.com/Threx-code/cordon/blob/main/NOTICE).
