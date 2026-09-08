# Architecture

**Product:** Cordon
**Module and CLI:** `cordon`
**Licence:** Apache-2.0 (open core)
**Implementation:** Python 3.11+, standard library only in the core

---

## 1. Architectural style

Cordon is built as **ports and adapters** (hexagonal architecture) around an immutable domain model.

- The **domain** (`core/models.py`) depends on nothing. It defines findings,
  rules, dependencies, repositories and results, and imports no other Cordon
  module.
- The **application core** (`core/engine.py`) orchestrates phases. It depends on
  the domain and on a set of `Protocol` definitions, never on a concrete
  detector, reporter, ecosystem or source.
- The **adapters** (`detect/`, `report/`, `ecosystems/`, `sources/`, `intel/`)
  implement those protocols and are discovered at runtime through entry points.

The dependency rule is one-directional and enforced by a test: nothing in
`core/` may import from `detect/`, `report/`, `ecosystems/` or `sources/`.

This is not architectural decoration. It buys four specific properties the
product requires:

| Property | How the style delivers it |
|---|---|
| **Extensibility without forking** | A new ecosystem, detector or reporter is a class implementing a protocol, registered by entry point. The engine never learns its name. |
| **Horizontal scalability** | Detectors are pure functions over immutable inputs with no shared state, so they run unchanged in a thread, a worker process, or a distributed queue. Scaling out is a deployment decision, not a rewrite. |
| **Testability** | Every phase can be driven with a hand-built domain object. Detectors are tested without a filesystem; reporters without a scan. |
| **Auditability** | Detection content lives in signed, versioned data, separate from engine code, so a security team can review rules without reading Python. |

### 1.1 Patterns used, and why

| Pattern | Where | Why here specifically |
|---|---|---|
| Dependency inversion via `Protocol` | detectors, reporters, ecosystems, sources, intel | Structural typing means a third-party plugin implements an interface without importing Cordon's base class, so plugins are not coupled to our release cycle. |
| Plugin registry over entry points | `core/registry.py` | Built-in components register through the same mechanism third parties use. There is no privileged path, so a broken plugin system fails for us first. |
| Strategy | match kinds, reporters, sources | Adding an output format or a match type is a new class, not a branch in a growing conditional. |
| Pipeline / phases | `core/engine.py` | Each phase has one input type and one output type, so a phase can be replaced, parallelised or cached in isolation. |
| Immutable value objects | the whole domain | Safe to share across processes, impossible to mutate a result post hoc, and free hashability for deduplication. |
| Specification | `core/policy.py` | Failure policy is a composable predicate over findings, so gate logic is testable without running a scan. |
| Layered configuration with a ceiling | `core/config.py` | Untrusted repository configuration must be able to describe a project without being able to disable its own inspection. |
| Streaming iterators | sources, reporters | Bounds memory on inputs of unknown size, which is a security requirement, not just an efficiency one. |

---

## 2. Governing constraints

Decisions, not preferences. Every later section is downstream of them.

### C1. The core has zero third-party runtime dependencies

`cordon_scanner.core`, `cordon_scanner.detect`, `cordon_scanner.report`, `cordon_scanner.rules` and `cordon_scanner.cli`
import nothing outside the standard library. Extras (`[ast]`, `[intel]`) are
opt-in and each must degrade to a documented reduced capability, never to an
error.

A security tool installs into a privileged position on every developer machine
and CI runner in an organisation, and its dependencies appear in the SBOM of
everyone who adopts it. A supply-chain scanner with a transitive dependency tree
is asking to become the incident it was bought to prevent. This constraint also
makes air-gapped installation a single wheel with nothing to vendor.

### C2. No network access at scan time unless explicitly enabled

Default `offline: true`. Advisory and reputation data ship as a local database.
`--online` is explicit, logs every host contacted, and can never be turned on by
a configuration file found inside the scanned repository.

### C3. The scan target is untrusted input, including its own configuration

A repository's `cordon_scanner.yaml` may **relax nothing** that organisation policy sets.
Precedence is fixed, and the org layer acts as a ceiling rather than a default:

```
CLI flags  >  organisation policy  >  repository cordon.yaml  >  built-in defaults
                     ^ ceiling: the repo layer is clamped to what policy permits
```

An attacker who can commit to a repository can commit a configuration file. If
that file can add an exclusion, disable a detector or lower a threshold, then
the first thing a payload ships with is a configuration change, and every
control below it is decorative.

### C4. Never execute code from the scan target

No import, no `node`, no `setup.py`, no build tool, no plugin loaded from the
target. Manifests are parsed by Cordon's own parsers; `setup.py` is treated as
source code to analyse, never as a module to import.

Invoking the ecosystem's own tooling to read metadata is the tempting shortcut,
and it is the exact behaviour the product exists to warn about. Once "run the
ecosystem's tool" is an acceptable pattern, the boundary has already moved, and
the end of that road is a resolver executing install hooks.

### C5. Determinism

Identical inputs produce byte-identical findings in a stable order. No timestamps
in finding bodies, sorted iteration everywhere, integer arithmetic in scoring,
and no dependence on worker completion order.

Required for baselines, for diffing two scans, for reproducible CI gates, and for
safe result caching. A cache is only sound if a cache hit is provably identical
to a cold run.

### C6. Anything that produces or suppresses a finding is Python

Other languages appear in exactly three slots, none of which contains detection
logic: optional prebuilt AST grammars, an optional native matcher accelerator
whose pure-Python fallback must produce byte-identical output, and packaging
shims (Action YAML, Dockerfile, hook shell).

### C7. Findings never leak what they found

Evidence is redacted by default: a match span, a hash of the matched bytes, and a
snippet masked according to the rule's evidence policy. A secret detector never
prints the secret. Reports travel further than the repository does.

---

## 3. System overview

```
                          ┌────────────────────────────────────────┐
                          │              Consumers                 │
                          │  CLI  ·  SDK  ·  GitHub Action  ·  CI  │
                          │  pre-commit hook  ·  service (later)   │
                          └──────────────────┬─────────────────────┘
                                             │  Scanner.scan(target) -> ScanResult
┌────────────────────────────────────────────▼───────────────────────────────────┐
│                            APPLICATION CORE (pure)                             │
│                                                                                │
│   Source ─► Inventory ─► Plan ─► Execute ─► Correlate ─► Judge ─► Report       │
│    (§5)       (§9)       (§6)     (§6)        (§7)       (§8)      (doc 03)    │
│                                                                                │
│   depends only on: domain model + protocols                                    │
└───────┬──────────────┬──────────────┬───────────────┬──────────────┬──────────┘
        │              │              │               │              │
   ┌────▼────┐   ┌─────▼─────┐  ┌─────▼─────┐   ┌─────▼─────┐  ┌────▼─────┐
   │ Sources │   │ Detectors │  │ Ecosystems│   │   Intel   │  │Reporters │
   │ adapters│   │  adapters │  │  adapters │   │  adapters │  │ adapters │
   └─────────┘   └───────────┘  └───────────┘   └───────────┘  └──────────┘

   Cross-cutting: Limits · Cache · Audit · Redaction · Rule registry
```

### 3.1 Package layout

```
src/cordon_scanner/
  __init__.py             Public SDK surface. Everything else is internal.
  version.py              Engine, rule-pack and schema versions

  core/                   Domain and application core. Imports no adapter.
    models.py             Findings, rules, dependencies, repositories, results
    errors.py             Typed errors mapped to exit codes
    config.py             Layered configuration with an enforced ceiling
    policy.py             Thresholds, failure rules, suppressions, baselines
    scoring.py            Explainable deterministic risk score
    registry.py           Plugin discovery and registration
    limits.py             Resource governance
    content.py            Lazy file content: bytes, text, lines, hashes
    walker.py             Traversal, ignore semantics, git awareness
    cache.py              Content-addressed incremental cache
    dedup.py              Deduplication and correlation
    redact.py             Evidence redaction
    audit.py              Structured audit log
    engine.py             Phase orchestration

  sources/                Adapters: directory, file, archive, git, package
  detect/                 Detector adapters
  rules/                  Rule loading, validation, compilation, packs
  ecosystems/             Package-ecosystem adapters
  langs/                  Language identification data
  report/                 Output adapters
  intel/                  Advisory and reputation providers, offline-first
  archive/                Hardened archive extraction
  cli/                    Argument parsing and command implementations
```

---

## 4. Domain model

Detailed in `core/models.py`. The load-bearing decisions:

### 4.1 Five categories

`MALICIOUS`, `SUSPICIOUS`, `VULNERABLE`, `POLICY`, `OPERATIONAL`.

The first four are the prompt's required distinction. The fifth exists because a
scan that timed out, or skipped files it could not read, is neither clean nor
compromised. Without a category for it, a degraded scan has two options and both
are wrong: report success, which is a false negative that looks like a pass, or
fail the build, which trains people to ignore the tool.

### 4.2 Severity and confidence are independent axes

Severity is impact if real. Confidence is probability it is real. Fusing them
into one "priority" number makes a rule set unshippable, because a
dynamic-execution call is high impact and only moderately indicative on its own:
one axis forces the author to choose between never firing and firing constantly.

`Confidence.HIGH` carries an enforced meaning -- the rule was evaluated against
the benign corpus and matched nothing -- so false-positive control is a load-time
invariant rather than a review-time opinion.

### 4.3 Fingerprints exclude position

```
fingerprint = sha256(rule_id ‖ path ‖ enclosing_symbol ‖ normalised_match)[:16]
```

Four features depend on this: deduplication, baselines, suppression matching, and
SARIF `partialFingerprints`.

Line numbers are deliberately excluded. Including position is the common mistake
and it is fatal to adoption: adding an import at the top of a file shifts every
line below it, every alert in that file re-fires as new, and people learn to
dismiss the tool in bulk.

---

## 5. Sources

A `Source` yields artefacts. The engine knows nothing else about targets.

```python
class Source(Protocol):
    name: str
    def probe(self, target: str) -> bool: ...
    def open(self, target: str, limits: Limits) -> Iterator[Artifact]: ...
    def metadata(self) -> SourceMetadata: ...
```

| Source | Target | Notes |
|---|---|---|
| `DirectorySource` | a path | Ignore rules applied during the walk; symlinks not followed out of root |
| `FileSource` | one file | Single-artefact scan |
| `ArchiveSource` | `zip tar tar.gz tgz whl jar nupkg gem crate apk` | Hardened extraction, section 10 |
| `WorkingTreeSource` | a directory | the default; files as they are on disk |
| `GitIndexSource` | a repository | `--staged` reads blobs from the git index, not the working tree |
| `GitPathSource` | a repository | `--tracked` and `--git-diff REF` narrow which files are examined |
| `PackageSource` | `pkg:npm/name@version` | Local cache, or download only under `--online` |
| `StdinSource` | `-` | Editor integrations |

**Staged scanning reads the git index, not the working tree.** This is a source
concern rather than a flag threaded through detectors, and it matters: a scanner
that reads from disk in staged mode can be defeated by staging a poisoned file
and restoring the clean version on disk, because the poisoned blob is what gets
committed while the clean one is what gets scanned. `GitSource` materialises the
staged blobs and scans those.

---

## 6. Detection engine

### 6.1 The detector contract

```python
class Detector(Protocol):
    id: str
    version: str
    categories: frozenset[Category]
    requires: DetectorRequirements       # content? ast? deps? repo? network?

    def applicable(self, ctx: ScanContext) -> bool:
        """Cheap check against the inventory. Performs no file reads."""

    def inspect(self, unit: Unit, ctx: ScanContext) -> Iterable[Finding]:
        """Pure. No I/O outside `unit`, no global state, safe to call from a
        worker process."""
```

Purity is enforced rather than requested. Detectors run in workers with no
network module imported and no writable path outside a scratch directory, and the
engine asserts that returned findings are located within the unit that was
passed. This is what makes distributed execution a deployment choice rather than
an engine change.

A `Unit` is whatever the detector declared it needs: one file, one manifest, the
resolved dependency graph, or the repository inventory. The engine batches units
per detector, so a detector that needs cross-file correlation sees the whole set,
and one that does not sees them one at a time.

### 6.2 Detectors

| Detector | Layer | Responsibility |
|---|---|---|
| `capability` | content | Behavioural primitives and composite rules over them |
| `obfuscation` | content | Entropy, escape runs, packer signatures, bidirectional and zero-width characters |
| `secrets` | content | Entropy plus shape plus context, hash-only evidence |
| `manifest` | package | Lifecycle-script allowlist, dependency source, per ecosystem |
| `lockfile` | package | Integrity hashes present, registry origin, resolution consistency |
| `dependency` | graph | Typosquatting, confusion, version anomaly, abandonment, advisories |
| `advisory` | graph | Known-malicious package, version or artefact hash |
| `ci` | config | Secret exposure, unpinned actions, dangerous trigger use |
| `container` | config | Fetch-and-execute in builds, unpinned bases, build-arg secrets |
| `iac` | config | Public exposure, privileged containers, host mounts |
| `repository` | repo | Scanner self-integrity, hook tampering, dormant controls |
| `script` | content | Shell and PowerShell: fetch-execute, persistence, reverse shells |

All twelve register through the same entry point a third party would use.

### 6.3 Layered execution

```
Layer 0  Inventory      repository shape, languages, ecosystems, hooks    (§9)
Layer 1  Cheap content  one pass over each file's bytes
Layer 2  Structural     parse manifests, lockfiles, CI configs, Dockerfiles
Layer 3  Semantic       AST rules where a grammar is available (optional extra)
Layer 4  Graph          resolved dependency graph, transitive analysis      (§10)
Layer 5  Correlation    composite rules across layers                       (§7)
```

Layer 1 is the hot path and its design decides whether the tool is adoptable at
all. A commit-time guard that costs noticeably more than a second gets bypassed,
and a bypassed guard protects nothing:

- All enabled regex rules compile once into a small number of **combined
  alternation patterns**, grouped by flags, with named groups mapping matches
  back to rule identifiers. Cost is O(bytes), not O(bytes x rules).
- A **literal prefilter** runs first. A file containing none of the required
  substrings skips the regex pass entirely, which in practice eliminates the
  large majority of files.
- Files are read once as `bytes` and matched as bytes; decoding happens only when
  a match needs evidence.
- Binary files are detected by a NUL byte in the first 8 KiB and excluded from
  content rules, so tracked images cannot produce coincidental matches.
- A file is skipped only for reasons that produce an `OPERATIONAL` finding.

### 6.4 Capability primitives: the portable core

Signature detection does not generalise. A rule written against a campaign's
indicators stops working when the campaign changes a string, and it never worked
for another language at all.

Capability detection generalises, because the primitives are forced by the
attacker's objective rather than chosen by them. To exfiltrate, code must read
something sensitive and send it somewhere. To run a second stage, it must decode
a payload and execute it. Those requirements hold in every language and there are
only a handful of them.

Each language plugin supplies patterns for the same six names:

| Primitive | JavaScript | Python | Shell | Java | Go |
|---|---|---|---|---|---|
| `DECODE` | `atob(`, `Buffer.from(...,'base64')` | `base64.b64decode`, `codecs.decode` | `base64 -d` | `Base64.getDecoder` | `base64.StdEncoding` |
| `EXECUTE` | `eval(`, `new Function(`, `vm.runIn` | `eval`, `exec`, `compile`, `pickle.loads` | `eval`, `source` | `ScriptEngine`, `defineClass` | `plugin.Open` |
| `SPAWN` | `child_process`, `execSync` | `subprocess`, `os.system`, `os.popen` | backticks, `$( )` | `Runtime.exec`, `ProcessBuilder` | `exec.Command` |
| `CREDENTIAL` | `process.env`, `.npmrc`, `.ssh/` | `os.environ`, `~/.aws`, `.pypirc` | `$HOME/.ssh` | `System.getenv` | `os.Getenv` |
| `EGRESS` | `fetch(`, `axios`, `sendBeacon(` | `requests`, `urllib`, `socket` | `curl`, `wget`, `/dev/tcp` | `HttpClient` | `http.Get`, `net.Dial` |
| `PERSIST` | shell profile writes, launchd | `crontab`, shell profile | `crontab`, systemd unit | - | - |

Composite rules are written **once**, against the names:

```
SUSPECT.DECODE_EXEC.001    DECODE and (EXECUTE or SPAWN)              same file
SUSPECT.EXFIL.001          CREDENTIAL and EGRESS and (EXECUTE or SPAWN)  same file
MALWARE.EXFIL.001          CREDENTIAL and EGRESS                  in an install hook
MALWARE.DROPPER.001        EGRESS and SPAWN                       in an install hook
```

**Execution context is a severity multiplier, not a separate rule.** The same
capability pair is moderate in application code and critical in a `postinstall`
hook, because install-time code runs unprompted, as the developer, with the
developer's full environment, before any test, review or container boundary
applies. Modelling context as a multiplier rather than duplicating rules is what
keeps the rule set small enough to audit.

### 6.5 Adding a language

Adding a new language is a data change:

```
langs/<lang>.toml             extensions, shebangs, comment and string syntax
rules/builtin/<lang>.yaml     capability primitives and language-specific rules
ecosystems/<eco>.py           optional: about 120 lines to parse its manifests
```

No core file changes. This is the test the architecture must keep passing.

---

## 7. Correlation, deduplication and risk

### 7.1 Correlation

Layer 5 receives all findings plus the inventory and produces:

- **Composite findings** from n-ary capability rules. Contributing findings are
  retained but demoted to `INFO` and linked, so a reviewer sees one failure with
  a visible chain instead of three unexplained ones.
- **Chain findings** for a malicious transitive dependency: one finding carrying
  the whole path, not one per hop.
- **Escalations** where context raises severity, with the escalation recorded in
  the explanation rather than applied invisibly.

### 7.2 Deduplication

Keyed on fingerprint. Identical fingerprints collapse with an occurrence count;
different rules at one location stay separate because they are different claims;
a composite absorbs its contributors by demotion rather than deletion.

### 7.3 Risk scoring

Explainable by construction: a declared sum of integer factors over a severity
base scaled by a confidence weight, clamped to 0-100.

| Factor | Points | Condition |
|---|---|---|
| base | 10 / 25 / 45 / 70 / 90 | INFO / LOW / MEDIUM / HIGH / CRITICAL |
| confidence weight | x0.5 / x0.75 / x1.0 / x1.1 | LOW / MEDIUM / HIGH / CONFIRMED |
| `install_time` | +15 | Executes during install or build |
| `credential_access` | +12 | Touches environment, key material or cloud tokens |
| `network_egress` | +10 | Outbound network capability present |
| `obfuscated` | +10 | Content is encoded, packed or escaped |
| `transitive_depth` | -2 per hop, floor -6 | Deeper dependencies are less directly controlled |
| `reachable` | +8 | Reachability analysis indicates the path is used |
| `direct_dependency` | +5 | Declared in the project's own manifest |
| `binary_payload` | +8 | Unexpected binary or executable content |
| `no_fix_available` | +5 | Vulnerability with no patched version |
| `dev_only` | -8 | Confined to a development dependency |

Every finding carries the factor list that produced its score, and weights live
in versioned policy. A score nobody can reconstruct is a score nobody trusts, and
a score nobody trusts gets configured away.

---

## 8. Rule engine

### 8.1 Rules are versioned data

Detection rules fail silently by nature. A path filter stops matching, a pattern
is invalidated by a syntax change, an escape is mangled in a refactor: the rule
matches nothing, the scan exits successfully, and no signal anywhere indicates a
problem. The gate looks green precisely because the check is broken.

Rules are therefore authored as YAML, versioned independently of the engine,
signed as a pack, and required to carry executable self-tests.

### 8.2 Pack format

```yaml
pack:
  id: cordon.javascript
  version: 1.0.0
  license: Apache-2.0
  requires_engine: ">=1.0,<2.0"

rules:
  - id: SUSPECT.DECODE_EXEC.001
    version: 1.0.0
    category: suspicious
    severity: high
    confidence: medium
    title: Encoded payload decoded and executed in the same file
    message: >
      This file decodes a string and passes the result to a dynamic-execution
      primitive. Together these are the standard second-stage loader shape:
      the payload is not visible in review because it is not present as code
      until runtime.
    remediation: >
      Remove the dynamic execution. If data must be decoded, decode it into a
      value, never into code.
    languages: [javascript, typescript]
    evidence_policy: masked
    match:
      kind: composite
      scope: file
      all:
        - capability: decode
        - any:
            - capability: execute
            - capability: spawn
    tests:
      positive:
        - "const p = atob(BLOB); eval(p);"
      negative:
        - "const decoded = atob(userAvatar); img.src = decoded;"
```

`tests` is mandatory: a pack with a rule lacking a positive and a negative case
fails to load. `provenance` is mandatory for `category: malicious`, and
`kind: incident` marks a rule as protected so it cannot be removed or weakened
without an explicit review trailer.

### 8.3 Match kinds

| Kind | Description | Layer |
|---|---|---|
| `literal` | Exact byte substring. Fastest; used for known indicators. | 1 |
| `regex` | Validated safe subset. No backreferences, no unbounded nesting. | 1 |
| `entropy` | Shannon entropy over a window with a shape guard. | 1 |
| `structural` | Query over a parsed manifest or configuration. | 2 |
| `ast` | Grammar query. Requires the `ast` extra; degrades with a note. | 3 |
| `graph` | Predicate over the dependency graph. | 4 |
| `composite` | Boolean expression over other rules, with a scope. | 5 |

Pattern safety is enforced at pack load, not at match time. A rule pack must not
be able to hang the scanner, and organisations author their own rules.

### 8.4 Suppression

```yaml
suppressions:
  - rule: SUSPECT.SPAWN.001
    path: tools/release.py
    justification: >
      Invokes git to read the commit being released. The value is provenance
      and cannot be supplied by hand without defeating its purpose.
    approved_by: security-team
    expires: 2027-01-01
```

A suppression names **a rule and a path together**, never one alone. A rule-only
suppression disables a detection everywhere, including where it would have
mattered. A path-only suppression -- the familiar directory exclusion -- exempts a
location from every rule, and vendored or generated directories are precisely
where a payload prefers to sit.

`justification` and `expires` are mandatory, the maximum lifetime is bounded, an
expired suppression stops suppressing and emits a `POLICY` finding, `MALICIOUS`
findings are not suppressible at repository level, and suppressed findings remain
in the output rather than disappearing from it.

---

## 9. Repository and project detection

Layer 0 produces an `Inventory`, which is what makes scanner selection automatic.

```
Repository
   ├─ VCS            git, shallow, default branch, submodules
   ├─ Languages      extension, shebang and content sniff, byte-weighted
   ├─ Ecosystems     manifests and lockfiles, with confidence
   ├─ Frameworks     detected from manifest dependencies and layout
   ├─ Build systems  make, gradle, bazel, cargo, msbuild
   ├─ CI systems     workflow directories and pipeline files
   ├─ Containers     Dockerfiles, compose files
   ├─ IaC            terraform, kubernetes, helm, cloudformation
   ├─ Install hooks  every path that executes during install or build
   └─ Projects       a monorepo is N projects, each with its own ecosystem
```

Every conclusion carries its evidence, so `cordon-scanner inventory` explains itself and
a wrong inference can be debugged rather than guessed at.

**Monorepos are modelled as N projects.** Detectors are selected and scoped per
project, so Python rules never run against a TypeScript subtree. Without this, a
polyglot repository gets the union of every rule applied to every file, producing
both false positives and, worse, false negatives when a noisy rule is disabled
globally to quieten one subtree.

**Install hooks are a first-class inventory output**, because execution context
is the largest risk multiplier in the scoring model.

---

## 10. Dependency analysis

### 10.1 Ecosystem contract

```python
class Ecosystem(Protocol):
    id: str
    purl_type: str
    manifest_globs: tuple[str, ...]
    lockfile_globs: tuple[str, ...]

    def parse_manifest(self, a: Artifact) -> Manifest: ...
    def parse_lockfile(self, a: Artifact) -> LockGraph: ...
    def lifecycle_hooks(self, m: Manifest) -> tuple[Hook, ...]: ...
    def normalize_name(self, name: str) -> str: ...
    def registry_hosts(self) -> frozenset[str]: ...
```

`normalize_name` matters more than it appears. Name equivalence rules differ per
ecosystem -- separator folding, case handling, group-and-artifact composition,
case-encoded module paths -- and typosquat detection is meaningless without them.
Getting this wrong is where most tools generate their false positives.

Planned for v1: npm, pypi, maven, gradle, cargo, gomod, nuget, composer,
rubygems, cocoapods, pub. Each is 100-250 lines and touches no core file.

### 10.2 Graph construction

Built from the **lockfile**. Never resolved over the network and never by
invoking the package manager (C2, C4): running the ecosystem's resolver means
executing untrusted tooling against attacker-controlled metadata, and it makes
results non-reproducible because a resolver consults a live registry.

The absence of a lockfile is itself a `POLICY` finding, because it means what
will be installed is not knowable in advance.

### 10.3 Analyses

| Analysis | Method | Category |
|---|---|---|
| Known malicious | Package URL or artefact hash against the local intel database | `MALICIOUS` / `CONFIRMED` |
| Known vulnerable | Range matching against the bundled advisory database | `VULNERABLE` |
| Typosquat | Edit distance, keyboard adjacency, and popularity of the target, all three required after name normalisation | `SUSPICIOUS` |
| Dependency confusion | An internal-scope name resolvable from a public registry, or a public name resolved from a private host | `SUSPICIOUS` |
| Non-registry source | Resolution from a git URL, archive URL or local path, which bypasses lockfile integrity and advisory matching in one move | `POLICY` / `SUSPICIOUS` |
| Missing integrity | Lockfile entry carrying no hash | `POLICY` |
| Version anomaly | A jump beyond one major, a version outside the declared range, a pre-release in a production lockfile | `SUSPICIOUS` |
| Stale security pin | A version pin written to satisfy an advisory that the pinned range no longer satisfies | `POLICY` / `HIGH` |
| Dormant control | A security setting placed in a file its tool does not read, or expressed in the wrong unit | `POLICY` / `HIGH` |
| Abandonment | Release age and archived status from local metadata | `POLICY` |
| Unexpected change | Lockfile diff against a baseline: new transitive packages, or a changed integrity hash for an unchanged version | `SUSPICIOUS` |

The last two are worth calling out because almost nothing ships them.

A **stale security pin** is a pin added to force a patched version that has since
fallen behind the advisory it was written for. It reads as protective in review
while holding a vulnerable version in place, which makes it worse than no pin at
all, and no advisory scanner detects it because the pin looks deliberate.

A **changed integrity hash for an unchanged version** means the registry content
was replaced under a name that had already been reviewed. It is only detectable
because baselines are first-class.

---

## 11. Hardening against hostile input

Full treatment in `02-THREAT-MODEL.md`. The architectural hooks:

- `Limits` is passed to every source and detector and is not optional.
- Reaching a limit produces an `OPERATIONAL` finding, never a silent skip, and
  `ScanResult.complete` records whether the scan was whole.
- `archive/safe.py` is the only code permitted to expand an archive. It enforces
  an incremental compression-ratio ceiling, rejects absolute and traversing
  paths, refuses links, and caps entry count and nesting depth.
- No path from the scan target reaches a shell. `subprocess` appears in exactly
  one module, wrapped with fixed argv, separators and timeouts.

---

## 12. Extension points

| Extension | Mechanism | Core change |
|---|---|---|
| New rule | YAML in a pack | none |
| New language | `langs/*.toml` plus a rule pack | none |
| New ecosystem | `Ecosystem` implementation | none |
| New detector | `Detector` implementation, entry point `cordon_scanner.detectors` | none |
| New reporter | `Reporter` implementation, entry point `cordon_scanner.reporters` | none |
| New source | `Source` implementation, entry point `cordon_scanner.sources` | none |
| New intel feed | `IntelProvider` implementation | none |
| Organisation policy | YAML | none |

Third-party plugins are discovered through entry points and are **disabled by
default**, requiring `--allow-plugins` or an explicit policy allowlist. A scanner
that silently loads executable plugins from its environment has the same shape as
the attacks it detects. Plugins are never loaded from the scanned repository
(C3, C4).
