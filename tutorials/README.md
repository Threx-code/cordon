# Cordon tutorials

> **For Cordon 0.6.0.** Using another version? Open the tutorials at its tag: `https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` prints the link for the version you have installed.

Short, diagram-first walkthroughs. Each one is a single use case: read the
picture, run the command, move on. They assume nothing beyond a terminal.

```
                        ┌───────────────────────────────────────────┐
                        │                  CORDON                   │
                        │   supply-chain security for a source tree │
                        └───────────────────────────────────────────┘
                                          │
        reads (never executes) ───────────┼─────────── answers, your code never leaves
                                          │
   ┌──────────────┬───────────────┬───────┴───────┬───────────────┬──────────────┐
   │  source code │  manifests &  │   advisory    │  provenance   │   CI / IaC   │
   │  (per-lang)  │  lockfiles    │   database    │  attestations │   configs    │
   └──────────────┴───────────────┴───────────────┴───────────────┴──────────────┘
```

## The map

```
  START HERE
    │
    ├─ 01  First scan .................. install, scan, read the output, exit codes
    ├─ 02  How detection works ......... the pipeline: sources → detectors → findings
    │
  BY WHAT YOU WANT TO CATCH
    ├─ 03  Malware & vulnerabilities ... advisory DB, typosquats, dependency confusion
    ├─ 04  Reachability ................ cut CVE noise without hiding anything
    ├─ 05  Provenance & attestation .... prove a package was built from its real source
    ├─ 06  Secrets & exfiltration ...... 61 secret rules, 13 exfiltration rules
    ├─ 07  CI/CD pipeline attacks ...... attacks on the pipeline, across seven CI systems
    ├─ 08  Containers, K8s & IaC ....... Dockerfile, compose, Kubernetes, Terraform
    │
  RUNNING IT FOR REAL
    ├─ 09  The advisory database ....... keep the intel fresh (OSV + signed bundle)
    ├─ 10  CI & git hooks .............. fail-on gates, SARIF, fail-closed pre-commit
    ├─ 11  Air-gapped .................. offline bundles, deterministic scans
    ├─ 12  Vetting a package ........... answer "should I install this?" before you do
    │
  GOING DEEPER
    ├─ 13  AST rules & capabilities .... how rules see through obfuscation ([ast-js])
    ├─ 14  Config, policy & baselines .. org ceilings, adopt-incrementally
    ├─ 15  Output formats .............. text | json | sarif | junit | markdown | github
    ├─ 16  The sandbox ................. the one component that executes, and its isolation
    ├─ 17  Source, build & binaries .... build systems, binaries, licences, scan scope
    ├─ 18  AI agents, MCP & skills ..... every agent's instruction, MCP and hook files
    ├─ 19  Release comparison .......... what changed since the version you trust
    ├─ 20  In the editor ............... findings on the line, in VS Code
    │
  ACROSS A TEAM
    ├─ 21  Dependency review ........... what an update adds, on every pull request
    ├─ 22  Incoming code ............... clone and pull, scanned before they land
    ├─ 23  Machines & vendor SBOMs ..... installed packages, images, supplier SBOMs
    ├─ 24  Policy for every repo ....... one ceiling, pinned by digest; pins kept current
    │
  REFERENCE
    ├─ 25  Every ecosystem ............. all 28: the files read, the checks, the commands
    ├─ 26  Every command ............... every command and option, from the parser itself
    ├─ 27  Every agent location ........ each agent's files, MCP configs, hooks and rules
    ├─ 28  Every rule .................. all 1,384 rules and every Agent Threat Rule
    │
  WHEN SOMETHING GOES WRONG
    └─ 29  Troubleshooting ............. exit codes, coverage notes, CI, hooks, images
```

## The one thing to remember

```
  Cordon READS. It never runs the code it is scanning, and it never sends anything
  about your code or dependencies anywhere unless you ask. By default it makes
  no network request at all; --offline (or CORDON_OFFLINE=1) guarantees it.
  A scan is safe to point at hostile packages and safe to run in an air-gap.
```

## Install

```
  pip install cordon-scanner            # base: zero third-party runtime deps
  pip install cordon-scanner[ast-js]    # + JavaScript/TypeScript semantic rules
  pip install cordon-scanner[attest]    # + sigstore provenance verification
```

Every extra is opt-in and degrades to a *stated* limit when absent — never a
silent gap, never a crash. See tutorials 09 and 05.

## New in 0.6.0

- **21 · Dependency review** — `review --base`: what an update adds, upgrades, downgrades and
  removes, with the releases fetched, verified and compared under `--online`.
- **22 · Incoming code** — `clone` and `pull` scan the commit from git's objects before it is
  checked out or merged, and `guard install --global` puts the same check on every clone,
  checkout and pull.
- **23 · Machines and vendor SBOMs** — `scan --host` for installed packages, and a supplier's
  CycloneDX or SPDX document.
- **24 · Policy for every repository** — an organisation policy pinned by digest, and every pin
  of Cordon kept current.
- **25 to 28 · The reference**: every ecosystem, every command, every AI agent and MCP
  location, and every rule, generated from the code so it cannot drift.
- **18** now covers the offline intent layer and remote MCP servers checked as they are served;
  **16** a second sandbox install with the clock moved ahead; **08** the images Kubernetes
  workloads run.

## New in 0.5.0

- **18 · AI agents, MCP servers and skills** — every agent's instruction, MCP and hook files,
  read without starting anything.
- **19 · What changed since the last release** — `--compare-with` and `--online`: new install
  hooks, new capabilities, new obfuscation, a new publisher.
- **20 · Findings in the editor** — the VS Code extension.
- **04 · Reachability** now covers Go at the level of the vulnerable function.
