# Operations

Performance, testing, enterprise deployment and roadmap.

---

## 1. Performance and scalability

### 1.1 Performance is a security property

A commit-time guard competes directly with the developer's attention. If it costs
noticeably more than a second, it gets bypassed, and a bypassed guard protects
nothing at all. The same logic applies one level up: a CI stage slow enough to be
resented acquires an exemption, and an exempted stage is not a gate.

So latency is not an efficiency concern here, it is the difference between a
control that runs and one that is routed around. Targets:

| Scenario | Target | Hard ceiling |
|---|---|---|
| Pre-commit, staged files only | < 300 ms | 1 s |
| 1,000-file repository, cold | < 2 s | 5 s |
| 50,000-file monorepo, cold | < 45 s | 3 min |
| 50,000-file monorepo, incremental | < 3 s | 10 s |
| Peak RSS, any scan | < 512 MB | 1 GB |

### 1.2 Why the naive shape is slow, and what replaces it

The obvious implementation evaluates every rule against every file
independently, which is O(files x rules) with a constant factor set by process or
match setup. On a few hundred files and a few dozen rules that is already tens of
thousands of operations, and it does not get better with a faster matcher. The
fix is to change the complexity, not the constant.

| Technique | Effect |
|---|---|
| **One combined automaton per pass** | All enabled regex rules compile into a small number of alternation patterns grouped by flags, with named groups mapping matches back to rule ids. Cost becomes O(bytes), not O(bytes × rules). |
| **Read each file exactly once** | `FileContent` is lazy and memoised: bytes, decoded text, line index, hashes. `mmap` above 1 MiB. Detectors share one instance. |
| **Bytes, not str** | Matching against `bytes` avoids decoding entirely for the roughly 99 percent of files with no match. Decoding happens only to build evidence. |
| **Process pool** | `ProcessPoolExecutor` over file batches. Batches are sized by cumulative bytes, not file count, so one huge file does not stall a worker while others idle. |
| **Cheap-first gating** | A literal prefilter (Aho-Corasick-style set of required substrings) runs before any regex. A file with none of the required literals skips the regex pass entirely. In practice this eliminates >90% of files. |
| **Binary short-circuit** | NUL in the first 8 KiB → skip content rules, matching `grep -I`. |
| **Ignore-first traversal** | Ignore patterns are evaluated on directories during the walk, so `node_modules/` is never descended into rather than being walked and filtered. |

### 1.3 Incremental scanning

The cache is content-addressed, so it is correct across branch switches, rebases
and CI runners with no shared state beyond the cache directory:

```
key = sha256( file_content ‖ rulepack_hash ‖ detector_versions ‖ config_hash )
```

Any rule change, config change or engine upgrade invalidates every entry, which is
the only safe behaviour — a stale cached "clean" is a false negative, and false
negatives in a security tool are the failure that matters.

Cache entries store the findings produced for that content, so a cache hit
produces identical output to a cold scan. This is verified by a test that runs a
corpus twice and asserts byte-identical results (and it is why determinism, C5, is
a hard requirement rather than a preference).

Graph-level analyses (dependency, correlation) are not file-cached; they are cheap
relative to content scanning and depend on the whole graph.

### 1.4 Monorepo strategy

Projects are discovered in Layer 0 and scanned independently:

- Detector selection is per project, so the Python detectors never run over the
  TypeScript subtree. This alone is most of the win: without it a polyglot
  repository gets the union of every rule applied to every file, which produces
  false positives immediately and false negatives soon after, when a noisy rule
  is disabled globally to quieten one subtree.
- `--project <path>` scans one project.
- `--git-diff` maps changed paths to affected projects; unaffected projects are
  skipped entirely, but their **dependency analysis still runs** — a malicious
  transitive dependency does not appear in a diff.
- Findings carry their project, so reports can be routed by CODEOWNERS.

### 1.5 Resource protection

Every limit from `02-THREAT-MODEL` is enforced in the same place it protects, and
**hitting a limit always produces an `OPERATIONAL` finding**. The scan result
carries `complete: bool`. A silent skip is treated as a bug: there is a test that
walks a corpus with limits set absurdly low and asserts that the number of
`OPERATIONAL` findings equals the number of skipped units.

### 1.6 What is deliberately not done

- **No incremental re-parse of dependency graphs.** Correctness over speed.
- **No result caching keyed by path.** Only by content — a path key is wrong the
  moment a file moves.
- **No background daemon in v1.** A long-lived process holding rule state is a
  larger attack surface and a support burden; revisit only if the server
  deployment demands it.

---

## 2. Testing strategy

A detection tool cannot be tested the way ordinary software is. Its failure mode
is silence: a rule that no longer matches produces no error, no warning and no
red build, and the pipeline stays green precisely because the check is broken.

Manual validation does not survive this, because it is not repeated. A payload
checked by hand during development proves the rule worked once, on that day, and
proves nothing after the next refactor. The strategy below is therefore built on
one principle: **every claim the tool makes about its own detection is an
executable test that runs on every commit.**

### 2.1 The corpus

```
corpus/
  benign/         Real-world-shaped code that must NOT produce findings
    javascript/  python/  go/  java/  rust/  shell/  php/  ruby/ …
    frameworks/  one directory per common framework's idiomatic layout
    minified/    genuinely minified bundles — the classic false-positive source
    generated/   protobuf, ORM, codegen output
  malicious/      Samples that MUST produce a specific finding
    incident/    the payloads that actually hit this organisation
    synthetic/   one directory per technique, each with an expectation file
  hostile/        Inputs that attack the scanner itself
    zipbomb/ nested-archive/ symlink-escape/ path-traversal/
    redos/ huge-line/ deep-nesting/ invalid-utf8/ null-bytes/
  performance/    Fixed synthetic repositories for latency budgets
```

Every malicious sample ships an expectation file:

```yaml
# corpus/malicious/synthetic/npm-postinstall-exfil/expected.yaml
must_find:
  - rule: MALWARE.EXFIL.001
    path: package.json
    min_confidence: high
must_not_find:
  - rule: SECRET.GENERIC.001      # the sample contains a decoy that is not a secret
```

The initial malicious corpus covers the techniques that define the threat, one
sample each, every one a permanent regression test:

1. An install hook that fetches a remote script and pipes it to a shell.
2. A base64 payload decoded and passed to dynamic evaluation.
3. An exfiltration host hidden behind escape encoding, feeding a process spawn.
4. An environment-variable beacon in a lifecycle script.
5. A multi-thousand-character single line hiding a payload off-screen.
6. A CI workflow serialising its secret context to an external host.
7. A build configuration file with a loader appended after the exported config.
8. A second stage retrieved from a source that cannot be taken down or
   domain-blocked.

### 2.2 Test layers

| Layer | What it proves | Gate |
|---|---|---|
| **Unit** | Parsers, limits, scoring arithmetic, fingerprint stability, config merge and clamping | 90% line coverage on `core/` |
| **Rule self-tests** | Every rule fires on its positives and not on its negatives. `cordon-scanner rules test`. | 100% of rules; a rule without tests fails to load |
| **Detection** | Every `corpus/malicious` sample produces its expected findings | 100%, no exceptions |
| **False-positive** | `corpus/benign` produces **zero** findings above `low` | 100%; a regression here blocks release as hard as a missed detection |
| **Baseline** | Every `confidence: high` rule has a recorded zero baseline over `corpus/benign` | Enforced at pack load |
| **Integration** | Ecosystem parsers against real manifests and lockfiles collected per ecosystem | Per ecosystem |
| **E2E** | CLI invocation, exit codes, each output format, SARIF schema validation | All five exit codes exercised |
| **Determinism** | Same input twice → byte-identical output; parallel vs `--jobs 1` → identical; cached vs cold → identical | Every CI run |
| **Hostile input** | Every `corpus/hostile` sample terminates within limits, produces an `OPERATIONAL` finding, and never writes outside the scratch dir | 100% |
| **Fuzz** | `atheris`/`hypothesis` over every parser: manifests, lockfiles, archives, configs, rule packs | Nightly, corpus-minimised, crashes become unit tests |
| **Performance** | The §1.1 targets, on a fixed synthetic repository | Nightly; a >20% regression fails |
| **Action** | The GitHub Action end-to-end via `act` and a real workflow in a fixture repo | Per release |
| **Self-scan** | Cordon scans itself with `--fail-on medium` | Every commit |

### 2.3 Non-negotiable rules

1. **Every newly discovered detection becomes a permanent regression test** before
   the rule merges. No exceptions.
2. **Every false positive reported by a user becomes a `corpus/benign` sample**
   before the fix merges. Otherwise the fix is untested and the FP returns.
3. **A rule may not ship at `confidence: high`** unless its baseline over
   `corpus/benign` is zero. Enforced at pack load, so the discipline cannot
   lapse through review pressure.
4. **A crash found by fuzzing becomes a unit test** with the minimised input.
5. **Removing or weakening a rule with `provenance.kind: incident`** requires an
   `INCIDENT-REVIEW` commit trailer; `cordon-scanner rules diff` enforces it in CI.

---

## 3. Enterprise deployment architecture

> **Design, not current state.** Of the channels and commands in this section,
> the wheel and the GitHub Action exist today. The container image, the
> standalone binary, the air-gapped bundle and `cordon-scanner bundle` are designed,
> not yet implemented. They are
> recorded here because the shape of the offline story constrains decisions
> being made now -- the advisory database is bundled and versioned with the
> release *because* of it -- and because an operator evaluating the tool for an
> air-gapped site needs to know both the intent and that it is not yet there.
>
> Labelled explicitly for the reason given in `03-INTERFACES.md`: an earlier
> version of these documents ran designed and delivered together, and readers
> reasonably assumed everything written in the present tense worked.


### 3.1 Distribution

| Channel | Artefact | Verification |
|---|---|---|
| PyPI | `cordon-scanner` wheel + sdist | PEP 740 attestations, Sigstore |
| pipx / uvx | `uvx cordon-scanner scan .` | as above |
| Container | `ghcr.io/cordon-dev/cordon:<ver>` distroless, non-root | cosign, referenced by digest |
| Standalone binary | PyInstaller single file, linux/macos/windows × amd64/arm64 | cosign + SHA256SUMS |
| GitHub Action | composite, pinned to a digest | cosign |
| Air-gapped bundle | `cordon-<ver>-offline.tar.gz`: wheel + rule packs + advisory DB + SBOM + signatures | detached signature + manifest |

The standalone binary exists specifically for CI images that have no Python, and
the container for everything else. Neither is the primary path — the wheel is,
because it is what makes the SDK usable.

### 3.2 Air-gapped operation

Offline is the **default**, not a mode (C2), so an air-gapped install is the
ordinary install:

```
cordon-1.0.0-offline.tar.gz
├── cordon-1.0.0-py3-none-any.whl
├── rulepacks/  cordon-builtin-1.4.0.tar.gz (+ .sig)
├── intel/      advisories-2026-09-08.db  (OSV-derived, CC-BY-4.0, NOTICE included)
│               malicious-packages-2026-09-08.db
│               package-metadata-2026-09-08.db   (popularity, age, archived flags)
├── SBOM.cdx.json  SBOM.spdx.json
├── MANIFEST.sha256
└── SIGNATURES/
```

Update flow inside the perimeter:

```
[internet-connected host]           [air gap]           [internal mirror]
cordon-scanner bundle create   ──── physical transfer ────►  cordon-scanner bundle verify
   ↓ signs                                              ↓ checks signature + hashes
bundle + signature                                   cordon-scanner bundle install
                                                        ↓
                                              CORDON_INTEL_DIR=/opt/cordon/intel
```

`cordon-scanner bundle verify` **fails closed**: an unsigned or hash-mismatched bundle is
refused, not warned about. The intelligence database records its own age, and a
scan using data older than `intel.max_age_days` (default 30) emits an
`OPERATIONAL` finding. Stale threat intelligence that presents itself as current
is the worst case for an air-gapped deployment: the scan passes, the report looks
identical to a good one, and nobody has a reason to investigate.

### 3.3 Deployment topologies

```
1. DEVELOPER          pipx install → cordon-scanner guard install → pre-commit --staged
                      offline, <300 ms, fail-closed shims in .git/hooks

2. CI                 container by digest, read-only mount, no network
                      SARIF → platform · JUnit → test tab · exit code → gate

3. CENTRAL POLICY     org policy in a git repo, consumed by CI via CORDON_POLICY
                      policy changes are PRs with CODEOWNERS review

4. MIRRORED           internal PyPI/registry mirror + internal intel mirror
                      nothing reaches the public internet

5. SERVICE (post-v1)  cordon-server: queue → workers → results store
                      horizontal scaling by worker count; the engine is already
                      a pure function, so this needs no engine change
```

### 3.4 Role-based configuration

Cordon has no user model and should not grow one. Roles are expressed through the
artefacts each role can change, enforced by the version-control system:

| Role | Owns | Enforced by |
|---|---|---|
| Security team | org policy, rule packs, suppression approvals, scoring weights | CODEOWNERS on the policy repo + branch protection |
| Platform / DevEx | CI templates, container digests, cache location | CODEOWNERS on `ci/` |
| Repository owner | `cordon_scanner.yaml` within the org ceiling, suppression *requests* | Repo CODEOWNERS |
| Developer | nothing that weakens a control | The ceiling (C3) + expiring suppressions |

This is deliberate. An RBAC system inside a CLI is a system that can be
misconfigured; git already has a reviewed, audited, diffable permission model, and
the existing CODEOWNERS setup already demonstrates it working.

### 3.5 Audit logging

Every scan optionally appends a structured JSON line:

```json
{
  "ts": "2026-09-08T14:22:31Z",
  "event": "scan.complete",
  "cordon_version": "1.0.0",
  "rulepack": "cordon-builtin@1.4.0",
  "rulepack_sha256": "9f3a1c…",
  "config_sha256": "1d0e77…",
  "policy": "acme-baseline@2026-09-08",
  "target_kind": "directory",
  "repo": "git@github.com:acme/frontend.git",
  "revision": "3601460…",
  "files_scanned": 412,
  "findings": {"critical": 1, "high": 0, "medium": 3, "suppressed": 2},
  "suppressions_applied": [
    {"rule": "SUSPECT.SPAWN.001", "path": "scripts/sync-core.mjs",
     "approved_by": "security-team", "expires": "2027-01-01"}
  ],
  "complete": true,
  "duration_ms": 2104,
  "exit_code": 1
}
```

**It records what was found and what was silenced, never file content.** The
`suppressions_applied` array is the important part: an auditor's first question is
what the tool was told to ignore, and answering it must not require reading every
repository's configuration file by hand.

### 3.6 Supply-chain security of Cordon itself

**Cutting a release.** The order matters, because it is what makes the Action's
hash pin true rather than aspirational:

```
build  ->  pin from the built artefacts  ->  publish those same artefacts
       ->  confirm the index serves what was uploaded
```

`scripts/pin_action_requirements.py --from-dist dist` takes the digests from the
files that are about to be uploaded, so the pin is correct by construction and
depends on no build being byte-reproducible. After publication,
`--from-pypi --check` reads the digests back from the index and fails if they
differ, which catches an upload that did not land as it was sent. Commit
`action/requirements.txt` and move the release tag onto that commit, so that
pinning the Action by SHA pins the download too. `.github/workflows/release.yml`
does all of this.


The product cannot be the next incident. Concretely:

- **Zero third-party runtime dependencies in the core** (C1) — the smallest
  possible attack surface, and an SBOM a human can read.
- **All build and CI dependencies pinned by hash**; all GitHub Actions pinned to
  commit SHAs. The action pinning is enforced by a test rather than by review,
  because a routine "bump the action version" commit is exactly what silently
  undoes it.
- **The Action verifies what it installs.** Pinning the Action to a commit SHA
  -- which its callers are told to do -- covers `action.yml` and nothing else.
  It says nothing about what pip then downloads, so a compromised index or
  release account would replace the scanner in every workflow using the Action
  and no pin would detect it. `action/requirements.txt` carries the digests of
  the published artefacts and the Action installs with `--require-hashes`, so
  pip refuses anything else. A ref with no pin refuses to install rather than
  installing unverified; `allow-unverified-install: true` overrides that, in
  the workflow file where it is reviewable, and says loudly what it costs.
- **Reproducible builds** with `SOURCE_DATE_EPOCH`; CI rebuilds each release
  independently and compares digests.
- **SBOM** (CycloneDX + SPDX) generated and signed per release.
- **Sigstore keyless signing** of every artefact; **SLSA build provenance**
  attested.
- **Release branch protected**, CODEOWNERS-reviewed, tags signed.
- **`cordon-scanner guard verify` runs on Cordon's own repository** in CI.
- **Cordon scans Cordon** on every commit at `--fail-on medium`.
- **Rule packs are separately signed and versioned**, so a rule update is not a
  code update and can be reviewed by security rather than engineering.
- **No post-install scripts, no build-time code execution** in the wheel. The
  package that warns about `postinstall` does not have one.

---

## 4. Implementation roadmap

Ordered so that each phase is independently useful and nothing is a throwaway
prototype. The existing Bash scanner stays in place until Phase 3 proves parity.

### Phase 1 — Core engine (foundation)
`core/` models, config with layering and clamping, policy, scoring, limits,
registry, content, walker, engine; `sources/` directory, file, git; the rule
loader and compiler; a `text` and `json` reporter; a minimal CLI (`scan`,
`version`).
**Exit criterion:** scans a directory with one built-in rule and emits
deterministic JSON.

### Phase 2 — Detection
`capability`, `obfuscation`, `manifest` (npm and pypi), `lockfile`, and
`repository` (self-integrity). The JavaScript and Python capability rule packs.
**Exit criterion:** every sample in `corpus/malicious` is detected with its
expected rule and confidence, and `corpus/benign` produces nothing above `low`.

### Phase 3 — Reporting and CI
`sarif`, `junit`, `markdown`, `github` reporters. Full CLI. Exit-code contract.
The GitHub Action. CI templates for GitLab, Jenkins, Azure.
**Exit criterion:** SARIF validates against the 2.1.0 schema and renders correctly
in GitHub Code Scanning with working `security-severity` and alert tracking.

### Phase 4 — Dependency analysis
Ecosystem plugins for npm, pypi, maven, gradle, cargo, gomod, nuget, composer,
rubygems, cocoapods, pub. Graph construction from lockfiles. Typosquat,
confusion, non-registry source, missing integrity, stale pin, dormant control.
The offline intel database and `cordon-scanner bundle`.
**Exit criterion:** correct graphs for a reference project per ecosystem, and
zero false typosquat positives across `corpus/benign`.

### Phase 5 — Breadth and false-positive control
`secrets`, `ci`, `container`, `iac`, `script` detectors. Language packs for the
remaining ecosystems. Baselines, suppression lifecycle, dedup and correlation.
The `[ast]` extra with tree-sitter.
**Exit criterion:** zero findings above `low` across the whole benign corpus;
`cordon-scanner baseline` in use.

### Phase 6 — Enterprise and hardening
Air-gapped bundles, signed releases, SBOM, provenance, audit log, org-policy
distribution, performance work against the §1.1 targets, fuzzing in CI.
**Exit criterion:** the 50,000-file monorepo target met; every §1.1 number
measured and tracked.

### Phase 7 — Adoption
Public release: signed artefacts, published Action, documentation site, rule
authoring guide, and a migration guide for teams replacing ad-hoc scripted
checks. Adoption runs Cordon alongside whatever a team already has until its
findings are a superset.
**Exit criterion:** a team can adopt Cordon by pinning a version and committing
one configuration file, with no vendored scanner code of their own.

### Explicitly deferred
Dynamic analysis / sandboxed execution; the hosted server; reachability analysis;
a web UI; ML-based classification. Each is a real capability and each is a
distraction until the static engine is trustworthy — because a sandbox escape in a
security tool is worse than the malware it was inspecting.
