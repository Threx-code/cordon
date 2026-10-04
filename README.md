<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Threx-code/cordon/main/docs/assets/logo-dark.svg">
  <img src="https://raw.githubusercontent.com/Threx-code/cordon/main/docs/assets/logo-light.svg" alt="Cordon" width="260">
</picture>

# Cordon

[![CI](https://github.com/Threx-code/cordon/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Threx-code/cordon/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/cordon-scanner?logo=pypi&logoColor=white)](https://pypi.org/project/cordon-scanner/)
[![Python](https://img.shields.io/pypi/pyversions/cordon-scanner)](https://pypi.org/project/cordon-scanner/)
[![Runtime dependencies](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen)](https://github.com/Threx-code/cordon/blob/v0.5.0/pyproject.toml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/Threx-code/cordon/blob/v0.5.0/LICENSE)
[![Coverage matrix](https://img.shields.io/badge/rules-1%2C356-informational)](https://github.com/Threx-code/cordon/blob/v0.5.0/docs/05-COVERAGE-MATRIX.md)
[![Ecosystems](https://img.shields.io/badge/ecosystems-17-informational)](https://github.com/Threx-code/cordon/blob/v0.5.0/docs/07-ECOSYSTEMS.md)

A language-agnostic software **supply-chain security scanner**. It reads source,
manifests, lockfiles, build scripts, CI config, Dockerfiles and IaC — and reports
malicious packages, install-time behaviour, leaked credentials and dependency risk.

It also reads what a repository hands an **AI coding agent**: instruction files,
skills, MCP server configs and their source, hooks and approvals — for every agent
in common use — against Cordon's own rules and 815 of the
[Agent Threat Rules](https://github.com/Agent-Threat-Rule/agent-threat-rules). An
optional judge (`--judge`) has a language model read that text for wordings no rule
anticipated ([tutorial 18](https://github.com/Threx-code/cordon/blob/v0.5.0/tutorials/18-agents-and-mcp.md)).

Seventeen package ecosystems, from npm and PyPI to Conan, Hex, CRAN and Bazel —
the file-by-file list, and which checks each one gets, is in
[docs/07-ECOSYSTEMS.md](https://github.com/Threx-code/cordon/blob/v0.5.0/docs/07-ECOSYSTEMS.md).

```
   ┌─────────────────────────────────────────────────────────────────────────┐
   │  Cordon READS.  It never executes the code it scans, and never sends    │
   │  anything about your code or your dependencies anywhere unless you      │
   │  ask.  By default it makes no network request at all; --offline         │
   │  guarantees it.  Safe on hostile packages, safe in an air-gap,          │
   │  and its results are reproducible.                                      │
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
> [tutorials](https://github.com/Threx-code/cordon/tree/v0.5.0/tutorials) are
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

   --notify slack,teams,webhook   post a failed gate (URLs from CORDON_NOTIFY_*)
   --clamav /run/clamd.sock       also hand each file to a local ClamAV daemon
   --judge cordon-cloud           also have a language model read agent-facing text
   --upload / --cloud-policy      Cordon Cloud: signed results, the org's policy
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
                          --vulnerabilities  advisory matches, KEV/EUVD marked
                          --ai               the AI bill of materials (CycloneDX 1.6)
   intel status|update    how current the signed threat-intel feed is
   login|logout|whoami    Cordon Cloud sign-in (device flow, SSO)
   runner                 run cloud scan jobs inside your network, outbound only
   agent inventory|report this machine's AI agents and MCP servers, for MDM
```

---

## Accuracy, measured

Every number is produced by a script in this repository, against code nobody
here wrote.

| corpus | size | result |
|---|---|---|
| Real malicious packages, by content alone | **39,002** (every DataDog npm and PyPI sample, and malregistry) | **94.1%** detected (npm 93.3%, PyPI 92.3%, malregistry 96.4%) |
| The same malware, against GuardDog | **995** | **95.4%** vs GuardDog's 83.9% |
| Popular packages wrongly blocked | top **1,000 PyPI + 1,000 npm** | **1.6%** vs GuardDog's 16.8% |
| CVEs agreed with Trivy and OSV-Scanner | **100 lockfiles** | **98.4%**, every disagreement explained |
| AI-agent attacks, Agent Threat Rules test cases | **4,026 attacks, 4,364 benign** | **97.7%** detected, 92.5% of benign left clean |
| AI-agent configs in real repositories, never tuned on | **372 repositories** | 10.5% warned, **1.1% blocked** (each block read and correct) |
| Widely used open-source repositories (0.4.0 run) | **1,427** | 85.4% pass the default gate |
| Reference infrastructure, as its vendors publish it (0.4.0 run) | **13 repos, 20,310 files** | 2,560 findings, 795 blocking |
| Known-malicious releases, by advisory | **521 pins, 8 ecosystems** | 100% reported |
| Known-vulnerable releases, by advisory | **940 pins, 11 ecosystems** | 100% reported |

Per ecosystem and per attack technique, with the method for each and what the
numbers are not: **[docs/08-ACCURACY.md](https://github.com/Threx-code/cordon/blob/v0.5.0/docs/08-ACCURACY.md)**.

## What fails a build, and how to change it

By default a finding fails the build when it says this code is compromised or
giving something away — malware, leaked credentials, obfuscation, exfiltration.
A posture choice a project made about its own infrastructure is reported and
does not fail: a security group open to the internet, `privileged: true`, a
Dockerfile doing `curl | sh`.

That split, the configuration file, the noise ladder and every exit code:
**[docs/10-CONFIGURATION.md](https://github.com/Threx-code/cordon/blob/v0.5.0/docs/10-CONFIGURATION.md)**.

Pre-commit, GitHub Actions, GitLab, Jenkins, containers and org-wide policy:
**[docs/09-INTEGRATIONS.md](https://github.com/Threx-code/cordon/blob/v0.5.0/docs/09-INTEGRATIONS.md)**.

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
| [tutorials/](https://github.com/Threx-code/cordon/tree/v0.5.0/tutorials) | Diagram-first walkthroughs, one per use case: scan, detection, reachability, provenance, CI, air-gap |
| [docs/01-ARCHITECTURE.md](https://github.com/Threx-code/cordon/blob/v0.5.0/docs/01-ARCHITECTURE.md) | Components, detection engine, rule format, extension points |
| [docs/02-THREAT-MODEL.md](https://github.com/Threx-code/cordon/blob/v0.5.0/docs/02-THREAT-MODEL.md) | Attacker profiles, trust boundaries, the constraints they imply |
| [docs/03-INTERFACES.md](https://github.com/Threx-code/cordon/blob/v0.5.0/docs/03-INTERFACES.md) | CLI, configuration and SDK reference; SARIF mapping |
| [docs/04-OPERATIONS.md](https://github.com/Threx-code/cordon/blob/v0.5.0/docs/04-OPERATIONS.md) | Deployment, rule authoring, performance, release process |
| [docs/05-COVERAGE-MATRIX.md](https://github.com/Threx-code/cordon/blob/v0.5.0/docs/05-COVERAGE-MATRIX.md) | Every rule that ships, by threat domain and attack category |
| [docs/06-SANDBOX.md](https://github.com/Threx-code/cordon/blob/v0.5.0/docs/06-SANDBOX.md) | The opt-in component that runs a package in isolation, and what it observes |
| [docs/07-ECOSYSTEMS.md](https://github.com/Threx-code/cordon/blob/v0.5.0/docs/07-ECOSYSTEMS.md) | Every ecosystem read, the files read for each, and which checks it gets |
| [docs/08-ACCURACY.md](https://github.com/Threx-code/cordon/blob/v0.5.0/docs/08-ACCURACY.md) | Detection rate by ecosystem and by attack technique, the method behind each number, and what they are not |
| [docs/09-INTEGRATIONS.md](https://github.com/Threx-code/cordon/blob/v0.5.0/docs/09-INTEGRATIONS.md) | Pre-commit, GitHub Actions, GitLab, Jenkins, containers, org-wide policy |
| [docs/10-CONFIGURATION.md](https://github.com/Threx-code/cordon/blob/v0.5.0/docs/10-CONFIGURATION.md) | `.cordon.yaml`, what fails a build, the noise ladder, exit codes, adopting on an existing codebase |
| [docs/11-RATIONALE.md](https://github.com/Threx-code/cordon/blob/v0.5.0/docs/11-RATIONALE.md) | What the other tools do, what they do not, and the gap this sits in |
| [docs/assets/](https://github.com/Threx-code/cordon/tree/v0.5.0/docs/assets) | The logo, as SVG: wordmark (light and dark), mark, and a filled square for an avatar |

### Project

| Document | Contents |
|---|---|
| [CHANGELOG.md](https://github.com/Threx-code/cordon/blob/v0.5.0/CHANGELOG.md) | What changed in each release, and what it changes for you |
| [CONTRIBUTING.md](https://github.com/Threx-code/cordon/blob/v0.5.0/CONTRIBUTING.md) | How to add a rule, and the evidence one needs before it ships |
| [GOVERNANCE.md](https://github.com/Threx-code/cordon/blob/v0.5.0/GOVERNANCE.md) | Who decides, and what a change has to prove |
| [SECURITY.md](https://github.com/Threx-code/cordon/blob/v0.5.0/SECURITY.md) | Reporting a vulnerability in Cordon itself |
| [SUPPORT.md](https://github.com/Threx-code/cordon/blob/v0.5.0/SUPPORT.md) | Which door to knock on, and what a useful report contains |
| [CODE_OF_CONDUCT.md](https://github.com/Threx-code/cordon/blob/v0.5.0/CODE_OF_CONDUCT.md) | What is not acceptable, and who to tell |
| [CITATION.cff](https://github.com/Threx-code/cordon/blob/v0.5.0/CITATION.cff) | How to cite this in research |

---

## Status

Beta, and the classifier says so. The detection engine, rule packs, seventeen
ecosystems, container images, the AI-agent chain, reporters, policy layer,
baselines, git-aware scanning and the advisory layer are implemented and tested;
`docs/03-INTERFACES.md` separates the commands that ship from those that are
designed. Interfaces may still change before 1.0, the bundled advisory set is the
malicious plus high/critical subset of OSV rather than all of it, four of the
seventeen ecosystems have no advisory feed to match against at all, and
reachability is modelled at its import tier, with function-level checks for Go
(from the symbols its database lists) and for PyPI and npm (from the functions an
advisory's text names, which can only raise a finding, never lower one) — none of it hidden: `cordon-scanner rules list`
shows what runs, `docs/07-ECOSYSTEMS.md` shows which checks each ecosystem gets,
and every reduction in coverage is reported as a finding rather than left for a
reader to infer.

## Licence

Apache-2.0. See [LICENSE](https://github.com/Threx-code/cordon/blob/v0.5.0/LICENSE) and [NOTICE](https://github.com/Threx-code/cordon/blob/v0.5.0/NOTICE).
