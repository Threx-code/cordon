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

## Accuracy, measured

Every number is produced by a script in this repository, against code nobody
here wrote.

| corpus | size | result |
|---|---|---|
| Widely used open-source repositories | **1,427** | 85.4% pass the default gate |
| Reference infrastructure, as its vendors publish it | **13 repos, 20,310 files** | 2,560 findings, 795 blocking |
| Real malicious packages, by content | **1,000** | 81.3% detected (npm 83.0%, PyPI 79.6%) |
| Known-malicious releases, by advisory | **521 pins, 8 ecosystems** | 100% reported |
| Known-vulnerable releases, by advisory | **940 pins, 11 ecosystems** | 100% reported |

Per ecosystem and per attack technique, with the method for each and what the
numbers are not: **[docs/08-ACCURACY.md](https://github.com/Threx-code/cordon/blob/main/docs/08-ACCURACY.md)**.

## What fails a build, and how to change it

By default a finding fails the build when it says this code is compromised or
giving something away — malware, leaked credentials, obfuscation, exfiltration.
A posture choice a project made about its own infrastructure is reported and
does not fail: a security group open to the internet, `privileged: true`, a
Dockerfile doing `curl | sh`.

That split, the configuration file, the noise ladder and every exit code:
**[docs/10-CONFIGURATION.md](https://github.com/Threx-code/cordon/blob/main/docs/10-CONFIGURATION.md)**.

Pre-commit, GitHub Actions, GitLab, Jenkins, containers and org-wide policy:
**[docs/09-INTEGRATIONS.md](https://github.com/Threx-code/cordon/blob/main/docs/09-INTEGRATIONS.md)**.

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
| [docs/08-ACCURACY.md](https://github.com/Threx-code/cordon/blob/main/docs/08-ACCURACY.md) | Detection rate by ecosystem and by attack technique, the method behind each number, and what they are not |
| [docs/09-INTEGRATIONS.md](https://github.com/Threx-code/cordon/blob/main/docs/09-INTEGRATIONS.md) | Pre-commit, GitHub Actions, GitLab, Jenkins, containers, org-wide policy |
| [docs/10-CONFIGURATION.md](https://github.com/Threx-code/cordon/blob/main/docs/10-CONFIGURATION.md) | `.cordon.yaml`, what fails a build, the noise ladder, exit codes, adopting on an existing codebase |
| [docs/11-RATIONALE.md](https://github.com/Threx-code/cordon/blob/main/docs/11-RATIONALE.md) | What the other tools do, what they do not, and the gap this sits in |
| [docs/assets/](https://github.com/Threx-code/cordon/tree/main/docs/assets) | The logo, as SVG: wordmark (light and dark), mark, and a filled square for an avatar |

### Project

| Document | Contents |
|---|---|
| [CHANGELOG.md](https://github.com/Threx-code/cordon/blob/main/CHANGELOG.md) | What changed in each release, and what it changes for you |
| [CONTRIBUTING.md](https://github.com/Threx-code/cordon/blob/main/CONTRIBUTING.md) | How to add a rule, and the evidence one needs before it ships |
| [GOVERNANCE.md](https://github.com/Threx-code/cordon/blob/main/GOVERNANCE.md) | Who decides, and what a change has to prove |
| [SECURITY.md](https://github.com/Threx-code/cordon/blob/main/SECURITY.md) | Reporting a vulnerability in Cordon itself |
| [SUPPORT.md](https://github.com/Threx-code/cordon/blob/main/SUPPORT.md) | Which door to knock on, and what a useful report contains |
| [CODE_OF_CONDUCT.md](https://github.com/Threx-code/cordon/blob/main/CODE_OF_CONDUCT.md) | What is not acceptable, and who to tell |
| [CITATION.cff](https://github.com/Threx-code/cordon/blob/main/CITATION.cff) | How to cite this in research |

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
