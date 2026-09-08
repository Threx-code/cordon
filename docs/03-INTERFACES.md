# Interfaces

CLI, SDK, GitHub Action, CI integration, configuration and reporting.

---

## 1. CLI design

### 1.1 Command surface

Shipping today:

```
cordon-scanner scan [TARGET]                 scan a directory, file or archive
cordon-scanner inventory [TARGET]            print what the repository is, and why
cordon-scanner guard verify|install|update   scanner self-integrity and git hooks
cordon-scanner rules list|show|test|diff     rule pack inspection and validation
cordon-scanner baseline create|compare       baseline management
cordon-scanner report convert                re-render a saved JSON result in another format
cordon-scanner config validate|explain       configuration checking
```

`cordon-scanner scan --advisories PATH` replaces the bundled advisory database with an
export of your own. The bundled set covers documented supply-chain incidents and
is what makes `Category.VULNERABLE` and `Confidence.CONFIRMED` reachable at all;
it is not a substitute for an advisory feed, and the flag is how a site with one
uses it offline.

Designed, not yet implemented:

```
cordon-scanner deps [TARGET]                 dependency graph and per-package analysis
cordon-scanner suppress list|add|prune       suppression lifecycle
cordon-scanner completion <shell>            shell completion
```

The split is stated rather than left to the reader because the alternative has
already cost something. An earlier version of this document listed the whole
surface as one block, and `cordon-scanner baseline` sat in it — documented, with the
`Baseline` class implemented, tested and exported from the SDK, and no command
to reach it. The documented adoption path did not exist.

Three verbs do real work (`scan`, `guard`, `baseline`); the rest are inspection.
That ratio is deliberate — every additional mutating command is a new way to
weaken the tool.

### 1.2 `cordon-scanner scan`

```
cordon-scanner scan [TARGET...]

TARGET DEFAULTS to "." and may be repeated. Accepts:
  ./path                directory
  ./file.py             single file
  ./pkg.tar.gz          archive (zip, tar*, whl, jar, nupkg, gem, crate, apk)
  pkg:npm/left-pad@1.3.0   package URL (requires --online or a local cache)
  -                     stdin

SELECTION
  --staged                    scan staged content from the git INDEX, not the worktree
  --git-diff <REF>            scan only paths changed against REF
  --since <REF>               alias for --git-diff
  --include <glob>            restrict to paths matching (repeatable)
  --exclude <glob>            skip paths matching (repeatable)
  --project <path>            in a monorepo, scan only this project

DETECTORS AND RULES
  --detector <id>             enable only these (repeatable)
  --no-detector <id>          disable (repeatable; org policy may forbid)
  --rules <path>              additional rule pack (repeatable)
  --profile <name>            strict | balanced | permissive | custom
  --rule <id>                 run only this rule (repeatable; for triage)

POLICY AND OUTPUT
  --severity <level>          report at or above: info|low|medium|high|critical
  --confidence <level>        report at or above: low|medium|high|confirmed
  --fail-on <level|category>  build-failure threshold (repeatable)
  --policy <file|url>         organisation policy (org layer)
  --baseline <file>           suppress findings present in the baseline
  --format <fmt>[:<path>]     text|json|sarif|junit|markdown|github (repeatable)
                              append :path to write that format to a file
  --output <path>             shorthand for a single --format
  --evidence <mode>           none|masked|full   (default masked)
  --quiet / --verbose / --no-color

EXECUTION
  --jobs <n>                  worker processes (default: cpu_count, capped at 16)
  --timeout <seconds>         total wall-clock budget
  --max-file-size <bytes>
  --cache <path> / --no-cache
  --incremental               reuse cached results for unchanged content
  --offline                   default; explicit for clarity in scripts
  --online                    permit named-host network lookups
  --fail-on-incomplete        treat a degraded scan as a failure
```

**Design notes.**

`--staged` is a *source selector*, not a filter, and it reads the git index
(§ `01-ARCHITECTURE` §4). That is the whole point: the add-then-restore bypass is
only closed if staged mode never touches the working tree.

A destination attaches to its format with a colon, because CI almost always
wants two outputs at once -- readable text on stdout and SARIF on disk:

```bash
cordon-scanner scan . --format text --format sarif:cordon.sarif
```

Two repeatable flags paired by position was the first design, and it is
error-prone in a way that fails silently. The natural reading of
`-f text -f sarif -o cordon.sarif` is that SARIF goes to the file; positional
pairing sends the *text* report there instead, and writing a report to a path
always succeeds, so nothing complains until something downstream tries to parse
it. `--output` survives as a shorthand for the single-format case and is refused
where it would be ambiguous.

`--no-detector` exists but org policy can forbid it (T6). Attempting a forbidden
disable is exit code 3, not a silent ignore.

There is no `--no-verify`, no `--force`, and no flag that disables the scan while
still exiting 0. The one escape hatch is the suppression file, which is
reviewable, expiring, and recorded in the output.

### 1.3 Exit codes — design and justification

```
0   Clean         Scan completed. No finding met the failure policy.
1   Findings      Scan completed. At least one finding met the failure policy.
2   Scanner error Cordon failed: I/O error, corrupt rule pack, internal fault.
3   Config error  Invalid configuration, invalid policy, or a forbidden override.
4   Incomplete    Scan degraded (timeout/limit) AND --fail-on-incomplete was set.
```

**Why this shape.**

- **0 and 1 are the only codes a normal gate distinguishes.** `if cordon-scanner scan .;
  then deploy; fi` is correct with no flags. Every other code is a failure, so a
  naive `!= 0` check is also correct and fails safe.
- **2 and 3 are separated deliberately.** A pipeline that cannot tell "the scanner
  broke" from "the code is bad" will eventually be configured to ignore both. 3
  specifically means *a human made a mistake in configuration*, which is
  actionable by a different person than 2.
- **4 exists because silently treating a timed-out scan as clean is the
  vulnerability.** It is opt-in rather than default, because making it default
  would break pipelines on the first large repository and train people to add
  `|| true` — which is worse than the failure it prevents.
- **Codes are stable API.** New codes may be added; existing ones never change
  meaning. Nothing above 4 will ever be used for a finding-severity distinction,
  because encoding severity into the exit code (`1=low, 2=high`) collides with
  every shell's convention and with codes 2 and 3 here.
- **126/127/128+N are left to the shell.** Cordon never returns them.

A two-code scheme (clean or not-clean) is the common starting point and it
collapses three different situations into one: a real finding, a broken scanner,
and a mistyped configuration key all become "the build is red". Once that
happens, the fastest way to a green pipeline is to stop running the tool. Codes
2, 3 and 4 exist so each situation reaches the person who can actually resolve
it.

### 1.4 Human output

Designed to be read in a terminal at 3 a.m. by someone who did not write the rule.

```
cordon 1.0.0 · rulepack cordon-builtin 1.4.0 (sha256:9f3a1c…)

CRITICAL  MALWARE.EXFIL.001                                    risk 92/100
  frontend/package.json:14  ·  scripts.postinstall
  confidence: high  ·  category: malicious  ·  detector: manifest

  The postinstall script reads environment variables and pipes them to a
  remote host. This executes as your user on every install, before any
  other control.

  evidence   scripts.postinstall = "node -e '…env…' | curl -X POST ██████████"
             match sha256:4b1f2e8a…

  why        DECODE      not required
             CREDENTIAL  process.env read           +12
             EGRESS      curl to a non-registry host +10
             CONTEXT     runs during install         +15
             base(CRITICAL) 90 × 1.00(high) = 90 → clamped 92

  fix        Remove the postinstall script. If a build step is genuinely
             required, move it to an explicit, reviewed build command and
             add the package to the build allowlist.

  refs       https://cordon.dev/rules/MALWARE.EXFIL.001

────────────────────────────────────────────────────────────────────────────
 1 critical   0 high   3 medium   0 low        2 suppressed   0 degraded
 412 files · 1,204 dependencies · 2.1s · complete
 FAILED: 1 finding at or above the failure threshold (critical)
```

The `why` block is the risk score rendering itself (§ `01-ARCHITECTURE` §6.3). A
score the user cannot reconstruct by hand is a score they will not trust, and a
score they do not trust is one they will configure away.

### 1.5 Other commands

`cordon-scanner rules test` runs every rule's declared positive and negative cases. This
is the mechanism that makes an inert rule impossible to ship. Detection rules
fail silently by nature: a path filter that no longer matches, a pattern
invalidated by a syntax change, an escaping error introduced in a refactor. The
rule stops matching anything, the scan still succeeds, and the gate looks green
precisely because the check is broken.

`cordon-scanner rules diff <ref>` fails if a rule with `provenance.kind: incident` was
removed or weakened without an `INCIDENT-REVIEW` trailer in the commit.
Incident-derived rules are the only ones known to have matched something that
actually arrived, and they are also the easiest to lose: an opaque indicator with
no obvious meaning is exactly what a well-intentioned cleanup deletes, and a
refactor can drop one while the diff appears to show only an improvement.

`cordon-scanner config explain` prints every effective setting with the layer it came
from, which is how T6 stays auditable.

`cordon-scanner suppress prune` -- designed, not yet implemented -- would remove expired
suppressions and report what it removed. Until it exists, an expired suppression
stops applying but stays in the file, and `cordon-scanner config explain` is what shows
that it is no longer in effect.

---

## 2. SDK / API design

The public surface is deliberately small. Everything not listed here is internal
and may change in a minor release.

```python
from cordon_scanner import Scanner, Config, Policy, Severity, Category

scanner = Scanner.for_target("./repository")
result  = scanner.scan("./repository")

for finding in result.findings:
    print(finding.rule_id, finding.severity, finding.location)

if result.violates(Policy.default()):
    raise SystemExit(1)
```

### 2.1 Public objects

| Object | Purpose | Stability |
|---|---|---|
| `Scanner` | Entry point. `scan()`, `scan_many()`, `inventory()`, `dependencies()` | stable |
| `Config` | Layered configuration. `from_file`, `from_dict`, `merge`, `explain` | stable |
| `Policy` | Thresholds, fail rules, suppressions, score weights | stable |
| `ScanResult` | `findings`, `inventory`, `dependencies`, `stats`, `complete`, `violates()` | stable |
| `Finding` | Frozen dataclass, § `01-ARCHITECTURE` §3.3 | stable |
| `Rule` / `RulePack` | Loaded rule metadata | stable |
| `Detector` | Protocol for third-party detectors | stable |
| `Reporter` | Protocol for third-party reporters | stable |
| `Ecosystem` | Protocol for third-party ecosystems | stable |
| `Repository` / `Project` / `Dependency` / `Package` | Inventory types | stable |
| `Severity` / `Confidence` / `Category` | Enums | stable |
| `CordonError` and subclasses | Typed errors mapped to exit codes | stable |

### 2.2 Guarantees

- **Everything returned is immutable.** `Finding`, `Dependency` and the inventory
  types are frozen dataclasses with `slots=True`. A caller cannot mutate a result
  and re-serialise it as if it came from a scan.
- **`Scanner` is reusable and thread-safe for `scan()`.** Rule compilation happens
  once per `Scanner`, not per scan — this matters for a server embedding it.
- **Bounded memory.** `limits.max_memory_bytes` caps the file content a scan
  holds, reporting an `OPERATIONAL` finding and marking the scan incomplete when
  it is reached. There is no streaming API: the engine discovers manifest hooks
  during the collection pass, and those change the context every later finding
  is scored against, so detection cannot begin until that pass completes. A
  `stream()` method used to be documented here and ran the whole scan before
  yielding anything.
- **No global state.** No module-level registry mutation at import time; the
  registry is constructed per `Scanner`. Two `Scanner`s with different configs can
  coexist in one process.
- **Deterministic ordering.** `result.findings` is sorted by
  `(path, rule_id, fingerprint)` — never by completion order.
- **`__all__` is the contract.** Anything not in `cordon_scanner.__all__` is internal.

### 2.3 Embedding example

```python
from cordon_scanner import Scanner, Config, Category

cfg = Config.from_dict({
    "scan": {
        "detectors": {"manifest": True, "dependency": True, "secrets": True},
        "offline": True,
        "limits": {"total_timeout": 300},
    },
})

scanner = Scanner(cfg)

for finding in scanner.scan("/srv/checkout").findings:
    if finding.category is Category.MALICIOUS:
        quarantine(finding)          # your code
```

---

## 3. GitHub Action design

### 3.1 Usage

```yaml
- uses: cordon-dev/cordon-action@v1
  with:
    severity: high
    sarif: true
```

That must be the whole minimal case. Everything else has a defensible default.

### 3.2 Full input surface

```yaml
- uses: cordon-dev/cordon-action@v1
  with:
    target: .                  # path, archive, or purl
    version: '1.x'             # Cordon version; resolved to an exact pinned digest
    config: cordon.yaml        # repo config
    policy: ''                 # org policy path or URL
    severity: high             # report threshold
    fail-on: high              # build-failure threshold
    sarif: true                # produce SARIF
    sarif-file: cordon.sarif
    upload-sarif: true         # upload to GitHub Code Scanning
    comment-pr: true           # comment findings on the PR
    comment-mode: summary      # summary | inline | both
    only-changed: false        # on PRs, scan only changed files
    baseline: ''               # baseline file path
    fail-on-incomplete: false
    evidence: masked           # none | masked | full
    jobs: '0'                  # 0 = auto
    working-directory: .
```

### 3.3 Permissions

Documented as the first thing in the README, because getting this wrong is the
most common failure:

```yaml
permissions:
  contents: read           # checkout
  security-events: write   # upload SARIF
  pull-requests: write     # only if comment-pr: true
```

### 3.4 Behaviour by trigger

| Trigger | Behaviour |
|---|---|
| `pull_request` | Scan the merge result. `only-changed: true` narrows to the diff, but **dependency and manifest analysis always runs on the full tree** — a malicious transitive dependency does not appear in the diff. |
| `push` | Full scan. SARIF uploaded with the branch ref so Code Scanning tracks it. |
| `schedule` | Full scan with `--online` permitted, so advisory data can refresh. This is the right place for network access: no PR is blocked on it. |
| `workflow_dispatch` | Full scan, all inputs overridable. |
| `merge_group` | Same as `pull_request`. |

**`pull_request_target` is refused.** If the action detects that event it fails
with an explanatory error, because that trigger runs with a writable token in the
context of the base repository while checking out untrusted head code — the exact
shape the tool exists to warn about. The action will not participate in it.

### 3.5 Security properties of the action itself

- **Never echoes findings' raw evidence into logs.** `evidence: masked` is the
  default, and the action sets `::add-mask::` for any value it must pass between
  steps.
- **Pins Cordon by digest.** The `version` input resolves to a container digest or
  a wheel hash recorded in the action, so a compromised tag cannot change what runs.
- **Composite action, not a JavaScript action**, so there is no `node_modules` in
  the action's own supply chain. The action is a Dockerfile reference to a signed
  distroless image plus a small shell entrypoint containing no detection logic (C6).
- **Verifies its own signature** with cosign before running, when a key is present.
- **Fails closed.** If Cordon cannot run, the step fails; it never passes with a
  warning. The existing `pre-commit` hook already encodes this reasoning and it was
  the right call: *"a missing, unreadable or non-executable scanner is treated as a
  FAILED scan, not as 'no scan configured'."*

### 3.6 PR comments

One comment, updated in place (never a new comment per push), keyed by a hidden
marker. Contains: a severity summary table, the top N findings with file/line
links, what changed since the last commit, and a link to the full SARIF in Code
Scanning. `comment-mode: inline` additionally posts review comments on the exact
diff lines, but only for findings inside the diff — commenting on unchanged lines
is how these bots get muted.

Evidence in comments is always masked regardless of `evidence:`, because a PR
comment is more public than a CI log.

---

## 4. CI/CD integration strategy

The strategy is one binary and one contract — exit codes plus a file — so no CI
system needs bespoke support in the engine.

| System | Integration | Ships as |
|---|---|---|
| **GitHub Actions** | Composite action + SARIF upload + PR comments | `action/` |
| **GitLab CI** | Job template emitting GitLab's Dependency/SAST report JSON, plus SARIF | `ci/gitlab/cordon.gitlab-ci.yml` |
| **Jenkins** | Declarative pipeline snippet; JUnit XML for the test-report UI; `warnings-ng` consumes SARIF | `ci/jenkins/Jenkinsfile.snippet` |
| **Azure DevOps** | Pipeline task YAML; JUnit for the tests tab; SARIF for Advanced Security | `ci/azure/cordon-task.yml` |
| **CircleCI / Buildkite / Drone / Woodpecker** | Generic container step | `ci/generic/` |
| **Pre-commit** | `.pre-commit-hooks.yaml` at the repo root, `--staged` mode | root |
| **Git hooks** | `cordon-scanner guard install`, fail-closed shims in `.git/hooks` | built in |

**Generic contract**, which is all a new system needs:

```bash
docker run --rm -v "$PWD:/scan:ro" \
  ghcr.io/cordon-dev/cordon:1.0.0@sha256:… \
  scan /scan --format sarif:/scan/cordon.sarif --fail-on high
# 0 clean · 1 findings · 2 error · 3 config · 4 incomplete
```

Read-only mount, no network, no host home directory — the same isolation posture
as `sandboxed-install.sh`.

### 4.1 Recommended gate policy

A gate set to critical-only reliably accumulates a backlog of high-severity
findings that nobody is required to act on, and a large share of those are
typically closed by a patch-level version bump. The thresholds below assume the
gate should be tight where the cost of stopping is low, and advisory where it is
not:

| Trigger | `--fail-on` | Rationale |
|---|---|---|
| Pre-commit | `critical` + `category:malicious` | Must be fast and must never be the thing people learn to bypass |
| Pull request | `high` | The gate that actually holds the line |
| Push to main | `high` | Same |
| Nightly / scheduled | `medium`, non-blocking, `--online` | Where the backlog becomes visible without blocking anyone |
| Release | `medium` + `--fail-on-incomplete` | The one place a degraded scan must not pass |

---

## 5. Configuration specification

### 5.1 Layering and precedence

```
CLI flags                       (highest)
  ↓
Organisation policy             --policy / CORDON_POLICY / /etc/cordon/policy.yaml
  ↓  ← acts as a CEILING on everything below (C3, T6)
Repository config               cordon.yaml / .cordon.yaml / [tool.cordon] in pyproject.toml
  ↓
Built-in defaults               (lowest)
```

### 5.2 Repository config

```yaml
# cordon.yaml — validated strictly; unknown keys are an error, not a warning.
version: 1

scan:
  severity_threshold: medium      # report at or above
  confidence_threshold: medium

  detectors:
    capability:   true
    obfuscation:  true
    secrets:      true
    manifest:     true
    lockfile:     true
    dependency:   true
    advisory: true
    ci:           true
    container:    true
    iac:          true
    repository:   true
    script:       true

  exclude:
    - node_modules/
    - vendor/
    - "**/*.generated.go"

  # Paths that are scanned but exempt from length-based heuristics only.
  minified:
    - "**/*.min.js"
    - "**/*.map"

  limits:
    max_file_bytes: 10485760
    max_total_bytes: 5368709120
    max_files: 200000
    per_file_timeout: 5
    total_timeout: 900
    max_archive_ratio: 200
    max_archive_depth: 3
    max_archive_entries: 50000

policy:
  fail_on:
    - critical
    - high
    - category: malicious        # any severity
  fail_on_incomplete: false

evidence: masked                 # none | masked | full

suppressions:
  - rule: SUSPECT.SPAWN.001
    path: scripts/sync-core.mjs
    justification: >
      Reads upstream git provenance for the vendored core. A commit id typed
      by a human is not provenance, and there is no way to ask a checkout
      what commit it is on without asking git.
    approved_by: security-team
    expires: 2027-01-01

rules:
  packs:
    - cordon-builtin
  extra:
    - .cordon/rules/org.yaml
```

### 5.3 Organisation policy

Everything in the repo config, plus the constraints that make it a ceiling:

```yaml
version: 1
name: acme-baseline
issued: 2026-09-08
issuer: security@acme.example

enforce:
  detectors_required: [capability, manifest, lockfile, dependency, advisory]
  min_severity_threshold: medium       # a repo may not set this higher
  max_total_timeout: 1800
  allow_network: false
  allow_plugins: false
  allow_extra_rule_packs: false

suppressions:
  max_duration_days: 90
  require_justification: true
  require_approver: true
  forbid_categories: [malicious]       # never suppressible at repo level
  forbid_path_only: true               # every suppression names a rule AND a path

scoring:
  weights:                             # versioned, diffable, never silent
    install_time: 15
    credential_access: 12
    network_egress: 10
    obfuscated: 10
    dev_only: -8

fail_on:
  - critical
  - high
  - category: malicious
```

### 5.4 Validation rules

Strict by construction, because a permissive config parser is a scanner-blinding
primitive (T6):

- **Unknown keys are errors** (exit 3), never warnings. A typo'd
  `sevrity_threshold` must not silently mean "default".
- **Every suppression requires `rule`, `path`, `justification` (≥40 chars) and
  `expires`.** There is no path-only or rule-only form.
- **`expires` must be in the future and within the org maximum.** An expired
  suppression stops suppressing *and* emits a `POLICY` finding.
- **A repo config that violates the org ceiling is exit 3 with the specific
  conflict named**, never silently clamped. Clamping quietly leaves the
  repository owner believing a setting is in force when it is not, and a control
  that reads as protective while doing nothing also stops anybody from looking
  for the real gap.
- **Config is data.** No expressions, no includes from URLs, no environment
  interpolation in a repo config (org policy may use env for secrets only).

`cordon-scanner config validate` exits 0/3 and is a one-line CI step. `cordon-scanner config
explain` prints the effective value of every setting with its originating layer.

---

## 6. Reporting and SARIF architecture

### 6.1 Separation

The reporting layer never sees the engine and the engine never imports a reporter:

```python
class Reporter(Protocol):
    id: str
    media_type: str
    def render(self, result: ScanResult, opts: ReportOptions) -> Iterator[bytes]: ...
```

`render` is a generator so large results stream to disk without materialising.
Reporters are pure functions of `ScanResult`; two reporters over one result cannot
disagree, and `cordon-scanner report convert` can re-render a saved JSON result into SARIF
months later without re-scanning.

### 6.2 Formats

| Format | Consumer | Notes |
|---|---|---|
| `text` | Humans | ANSI colour, auto-disabled when not a TTY or when `NO_COLOR` is set |
| `json` | Automation, the canonical form | Schema-versioned; every other format is derivable from it |
| `sarif` | GitHub Code Scanning, Azure DevOps, DefectDojo | SARIF 2.1.0 |
| `junit` | Jenkins, Azure, CircleCI test tabs | One testcase per rule; failures carry the finding |
| `markdown` | PR comments, summaries | Also drives `$GITHUB_STEP_SUMMARY` |
| `github` | Actions annotations | `::error file=…,line=…::` |
| `cyclonedx` | SBOM consumers | Dependency inventory with `vulnerabilities` |
| `sbom-spdx` | SBOM consumers | SPDX 2.3 |

**JSON is canonical.** SARIF, JUnit and Markdown are transformations of it. This
is what makes `report convert` possible and what guarantees the formats cannot
drift apart.

### 6.3 SARIF mapping

The mapping is where most tools produce technically-valid but practically-useless
SARIF. Decisions:

| SARIF field | Cordon source | Note |
|---|---|---|
| `tool.driver.name` | `"Cordon"` | |
| `tool.driver.version` | engine version | |
| `tool.driver.rules[]` | every rule that *could* fire, not only those that did | Code Scanning needs the full catalogue to render rule pages |
| `rules[].id` | `Finding.rule_id` | `MALWARE.EXFIL.001` |
| `rules[].defaultConfiguration.level` | severity → `error`/`warning`/`note` | critical+high → `error`; medium → `warning`; low+info → `note` |
| `rules[].properties.security-severity` | risk score as a string `"9.2"` | **This is what GitHub actually sorts and filters on.** Score/10, one decimal. |
| `rules[].properties.tags` | `["security", category, ecosystem, …]` | `security` tag is required for Code Scanning to treat it as a security alert |
| `rules[].help.markdown` | message + remediation + explanation | The rule page a developer lands on |
| `results[].ruleId` | `Finding.rule_id` | |
| `results[].level` | may differ from default when confidence lowers it | |
| `results[].message.text` | `Finding.message` | Never contains evidence |
| `results[].locations[]` | `Location` → `physicalLocation` with `region` | Byte offsets included alongside line/col |
| `results[].partialFingerprints.cordonFingerprint/v1` | `Finding.fingerprint` | **Load-bearing:** this is how Code Scanning tracks an alert across commits without re-alerting on a reformat |
| `results[].suppressions[]` | suppression with justification | Suppressed findings are emitted, not dropped |
| `results[].properties.risk` | full factor breakdown | Preserves explainability into the SARIF |
| `results[].relatedLocations[]` | correlated findings | The chain for a composite finding |
| `runs[].invocations[0].executionSuccessful` | `result.complete` | A degraded scan says so in the SARIF |
| `runs[].automationDetails.id` | `cordon/<profile>` | Groups runs in Code Scanning |
| `runs[].versionControlProvenance` | repo URI + revision | |

Two properties carry disproportionate weight and are worth stating explicitly:
`security-severity` is what GitHub sorts on (a SARIF without it renders every
finding as equally important), and `partialFingerprints` is what prevents an
alert storm every time a file is reformatted.

### 6.4 Redaction in reports

`evidence: masked` is applied **at finding construction**, not at render time, so
no reporter can accidentally emit unredacted content. `full` requires an explicit
flag and is refused entirely for `secrets`-category findings. Markdown and
`github` formats force masking regardless of setting, because their output is more
public than a log file.
