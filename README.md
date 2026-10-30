<!-- mcp-name: io.github.threx-code/cordon -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.svg">
  <img src="docs/assets/logo-light.svg" alt="Cordon" width="240">
</picture>

**A supply-chain security scanner that reads every dependency before it runs.**

[![CI](https://github.com/Threx-code/cordon/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Threx-code/cordon/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/cordon-scanner?logo=pypi&logoColor=white)](https://pypi.org/project/cordon-scanner/)
[![Python](https://img.shields.io/pypi/pyversions/cordon-scanner)](https://pypi.org/project/cordon-scanner/)
[![Runtime dependencies](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen)](https://github.com/Threx-code/cordon/blob/v0.6.0/pyproject.toml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/Threx-code/cordon/blob/v0.6.0/LICENSE)
[![Coverage matrix](https://img.shields.io/badge/rules-1%2C489-informational)](https://github.com/Threx-code/cordon/blob/v0.6.0/docs/05-COVERAGE-MATRIX.md)
[![Ecosystems](https://img.shields.io/badge/ecosystems-28-informational)](https://github.com/Threx-code/cordon/blob/v0.6.0/docs/07-ECOSYSTEMS.md)

Attackers stopped breaking in and started being installed: a typosquatted package, a release
pushed with a stolen token, a workflow that prints its secrets, an MCP server that tells your
coding agent to read `~/.ssh`. Cordon reads all of it before any of it runs: source, manifests,
lockfiles, build scripts, CI config, Dockerfiles, IaC, container images, and everything a
repository hands an AI coding agent. It never executes what it scans, it adds no runtime
dependency to your build, and it works offline.

## Sixty seconds

```bash
pipx install cordon-scanner
cordon-scanner scan .
```

<img src="docs/assets/terminal.svg" alt="cordon-scanner in a terminal: its home screen, then a repository scanned (nine findings fail the build), an npm package fetched and verified (clean), and a container image (414 findings across its OS packages)" width="100%">

<sub>A recording of the scanner itself, not a mock-up: `scripts/build/record_terminal.sh` records
it (the first command with `FORCE_COLOR=1`, so the pipe keeps its colour) and
`scripts/build/render_terminal.py` replays it. The repository scanned is built from the project's
own test corpus.</sub>

## What it catches

| | What Cordon finds | For example |
|---|---|---|
| **Malware** | Install hooks that steal, droppers, wipers, poisoned models, obfuscated loaders, known-malicious releases | `MALWARE.EXFIL.001` |
| **Leaked credentials** | Cloud keys, tokens and private keys, even split across string literals; reported by hash, never printed | `SECRET.AWS.ACCESS_KEY.001` |
| **AI agents and MCP** | Instruction files, skills, MCP servers and their source, hooks and approvals | `SUSPECT.MCP.TOOL_DESCRIPTION.001` |
| **CI/CD pipelines** | Secrets sent out, expression injection, untrusted checkouts, on GitHub, GitLab, Jenkins and more | `MALWARE.CI.SECRET_EXFIL.001` |
| **Dependencies** | Known-malicious and exploited versions, typosquats, provenance that does not verify, release diffs | `VULNERABLE.DEPENDENCY.EXPLOITED.001` |
| **Containers and IaC** | Images' OS packages, Dockerfiles, Kubernetes, Terraform, Helm and Ansible | `SUSPECT.K8S.RBAC_WILDCARD.001` |

Every rule that ships, by threat domain:
[docs/05-COVERAGE-MATRIX.md](https://github.com/Threx-code/cordon/blob/v0.6.0/docs/05-COVERAGE-MATRIX.md).

### Twenty-eight ecosystems

<!-- marks:packages -->
<table>
<tr><td><img src="docs/assets/marks/npm.svg" width="20" height="20" align="center" alt=""> npm</td><td><img src="docs/assets/marks/pypi.svg" width="20" height="20" align="center" alt=""> PyPI</td><td><img src="docs/assets/marks/cargo.svg" width="20" height="20" align="center" alt=""> Cargo</td><td><img src="docs/assets/marks/gomod.svg" width="20" height="20" align="center" alt=""> Go modules</td><td><img src="docs/assets/marks/maven.svg" width="20" height="20" align="center" alt=""> Maven</td><td><img src="docs/assets/marks/gradle.svg" width="20" height="20" align="center" alt=""> Gradle</td></tr>
<tr><td><img src="docs/assets/marks/nuget.svg" width="20" height="20" align="center" alt=""> NuGet</td><td><img src="docs/assets/marks/rubygems.svg" width="20" height="20" align="center" alt=""> RubyGems</td><td><img src="docs/assets/marks/composer.svg" width="20" height="20" align="center" alt=""> Composer</td><td><img src="docs/assets/marks/hex.svg" width="20" height="20" align="center" alt=""> Hex</td><td><img src="docs/assets/marks/pub.svg" width="20" height="20" align="center" alt=""> Pub</td><td><img src="docs/assets/marks/cocoapods.svg" width="20" height="20" align="center" alt=""> CocoaPods</td></tr>
<tr><td><img src="docs/assets/marks/swift.svg" width="20" height="20" align="center" alt=""> Swift</td><td><img src="docs/assets/marks/conan.svg" width="20" height="20" align="center" alt=""> Conan</td><td><img src="docs/assets/marks/vcpkg.svg" width="20" height="20" align="center" alt=""> vcpkg</td><td><img src="docs/assets/marks/conda.svg" width="20" height="20" align="center" alt=""> Conda</td><td><img src="docs/assets/marks/cran.svg" width="20" height="20" align="center" alt=""> CRAN</td><td><img src="docs/assets/marks/haskell.svg" width="20" height="20" align="center" alt=""> Hackage</td></tr>
<tr><td><img src="docs/assets/marks/julia.svg" width="20" height="20" align="center" alt=""> Julia</td><td><img src="docs/assets/marks/opam.svg" width="20" height="20" align="center" alt=""> opam</td><td><img src="docs/assets/marks/nix.svg" width="20" height="20" align="center" alt=""> Nix</td><td><img src="docs/assets/marks/homebrew.svg" width="20" height="20" align="center" alt=""> Homebrew</td><td><img src="docs/assets/marks/bazel.svg" width="20" height="20" align="center" alt=""> Bazel</td></tr>
</table>
<!-- /marks -->

<!-- marks:infrastructure -->
<table>
<tr><td><img src="docs/assets/marks/githubactions.svg" width="20" height="20" align="center" alt=""> GitHub Actions</td><td><img src="docs/assets/marks/terraform.svg" width="20" height="20" align="center" alt=""> Terraform</td><td><img src="docs/assets/marks/helm.svg" width="20" height="20" align="center" alt=""> Helm</td><td><img src="docs/assets/marks/ansible.svg" width="20" height="20" align="center" alt=""> Ansible</td><td><img src="docs/assets/marks/docker.svg" width="20" height="20" align="center" alt=""> container images</td></tr>
</table>
<!-- /marks -->

The file-by-file list, and which checks each ecosystem gets:
[docs/07-ECOSYSTEMS.md](https://github.com/Threx-code/cordon/blob/v0.6.0/docs/07-ECOSYSTEMS.md).

### Seventeen AI coding agents

<!-- marks:agents -->
<table>
<tr><td><img src="docs/assets/marks/claude.svg" width="20" height="20" align="center" alt=""> Claude Code</td><td><img src="docs/assets/marks/cursor.svg" width="20" height="20" align="center" alt=""> Cursor</td><td><img src="docs/assets/marks/copilot.svg" width="20" height="20" align="center" alt=""> GitHub Copilot</td><td><img src="docs/assets/marks/windsurf.svg" width="20" height="20" align="center" alt=""> Windsurf</td><td><img src="docs/assets/marks/gemini.svg" width="20" height="20" align="center" alt=""> Gemini CLI</td><td><img src="docs/assets/marks/openai.svg" width="20" height="20" align="center" alt=""> OpenAI Codex</td></tr>
<tr><td><img src="docs/assets/marks/kiro.svg" width="20" height="20" align="center" alt=""> Kiro</td><td><img src="docs/assets/marks/aws.svg" width="20" height="20" align="center" alt=""> Amazon Q</td><td><img src="docs/assets/marks/jetbrains.svg" width="20" height="20" align="center" alt=""> JetBrains Junie</td><td><img src="docs/assets/marks/augment.svg" width="20" height="20" align="center" alt=""> Augment</td><td><img src="docs/assets/marks/trae.svg" width="20" height="20" align="center" alt=""> Trae</td><td><img src="docs/assets/marks/roo.svg" width="20" height="20" align="center" alt=""> Roo Code</td></tr>
<tr><td><img src="docs/assets/marks/continue.svg" width="20" height="20" align="center" alt=""> Continue</td><td><img src="docs/assets/marks/zed.svg" width="20" height="20" align="center" alt=""> Zed</td><td><img src="docs/assets/marks/goose.svg" width="20" height="20" align="center" alt=""> goose</td><td><img src="docs/assets/marks/opencode.svg" width="20" height="20" align="center" alt=""> opencode</td><td><img src="docs/assets/marks/cline.svg" width="20" height="20" align="center" alt=""> Cline</td></tr>
</table>
<!-- /marks -->

For each, Cordon reads the instruction files, skills, MCP server configs and their source, hooks
and approvals, against its own rules and 815 of the
[Agent Threat Rules](https://github.com/Agent-Threat-Rule/agent-threat-rules). An optional judge
(`--judge`) has a language model read that text for wordings no rule anticipated
([tutorial 18](https://github.com/Threx-code/cordon/blob/v0.6.0/tutorials/18-agents-and-mcp.md)).

## Measured, not claimed

| | Result |
|---|---|
| Real malicious packages (39,328: npm, PyPI, AI skills, IDE extensions) | **94.2%** detected |
| The same malware against GuardDog (a fixed-seed draw of 498) | **95.2%**, against GuardDog's 85.5% |
| Popular packages wrongly blocked (top 1,000 PyPI + 1,000 npm) | **1.6%**, against GuardDog's 16.8% |
| AI-agent attacks (4,034 Agent Threat Rules test cases) | **97.7%** detected |

Every number comes from a script in this repository, run against code nobody here wrote. All twelve
measurements, the method behind each and what they are not: [docs/08-ACCURACY.md](https://github.com/Threx-code/cordon/blob/v0.6.0/docs/08-ACCURACY.md).

## How it works

1. **Target**: a repository, an archive, a package before you install it, a container image, or git history.
2. **Identify**: its languages, ecosystems, manifests and lockfiles.
3. **Detect**: 1,489 rules, code reading, binary analysis and the AI-agent chain.
4. **Decide**: score, policy and baseline settle what fails the build.
5. **Report**: text, JSON, SARIF, JUnit, GitHub annotations, SBOM.

Cordon never executes the code it scans, and sends nothing about your code anywhere unless you ask.
By default it asks OSV which advisories changed since its intel was built, naming no package;
`--offline` makes no request at all.

## Install

```bash
pipx install cordon-scanner                    # or: pip install cordon-scanner
docker run --rm -v "$PWD:/scan" ghcr.io/threx-code/cordon:<version>
```

Python 3.11 to 3.13 on Linux, macOS and Windows, with zero third-party runtime dependencies. The
image and the Action are distroless, non-root, signed with `cosign` and carry SLSA provenance; pin
them by digest, not by tag.

## Into your pipeline

```yaml
permissions:
  contents: read          # checkout
  security-events: write  # upload SARIF

jobs:
  supply-chain:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Threx-code/cordon/action@v0.6.0   # pin to a commit sha in production
        with:
          fail-on: high
          sarif: true
```

A finding fails the build when it says the code is compromised or giving something away; a posture
choice about your own infrastructure is reported, not failed. Exit codes: `0` clean, `1` findings,
`2` scanner error, `3` configuration error, `4` incomplete. Pre-commit, GitLab, Jenkins and
org-wide policy: [docs/09-INTEGRATIONS.md](https://github.com/Threx-code/cordon/blob/v0.6.0/docs/09-INTEGRATIONS.md).

## Documentation

[Tutorials](https://github.com/Threx-code/cordon/tree/v0.6.0/tutorials) ·
[Every command](https://github.com/Threx-code/cordon/blob/v0.6.0/tutorials/26-every-command.md) ·
[Configuration](https://github.com/Threx-code/cordon/blob/v0.6.0/docs/10-CONFIGURATION.md) ·
[Architecture](https://github.com/Threx-code/cordon/blob/v0.6.0/docs/01-ARCHITECTURE.md) ·
[Threat model](https://github.com/Threx-code/cordon/blob/v0.6.0/docs/02-THREAT-MODEL.md) ·
[Interfaces and SDK](https://github.com/Threx-code/cordon/blob/v0.6.0/docs/03-INTERFACES.md) ·
[Coverage matrix](https://github.com/Threx-code/cordon/blob/v0.6.0/docs/05-COVERAGE-MATRIX.md) ·
[Ecosystems](https://github.com/Threx-code/cordon/blob/v0.6.0/docs/07-ECOSYSTEMS.md) ·
[Accuracy](https://github.com/Threx-code/cordon/blob/v0.6.0/docs/08-ACCURACY.md) ·
[Changelog](https://github.com/Threx-code/cordon/blob/v0.6.0/CHANGELOG.md) ·
[Contributing](https://github.com/Threx-code/cordon/blob/v0.6.0/CONTRIBUTING.md) ·
[Security](https://github.com/Threx-code/cordon/blob/v0.6.0/SECURITY.md)

Licensed under Apache-2.0: see [LICENSE](https://github.com/Threx-code/cordon/blob/v0.6.0/LICENSE) and
[NOTICE](https://github.com/Threx-code/cordon/blob/v0.6.0/NOTICE).
