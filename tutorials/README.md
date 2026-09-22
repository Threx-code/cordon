# Cordon tutorials

Short, diagram-first walkthroughs. Each one is a single use case: read the
picture, run the command, move on. They assume nothing beyond a terminal.

```
                        ┌───────────────────────────────────────────┐
                        │                  CORDON                   │
                        │   supply-chain security for a source tree │
                        └───────────────────────────────────────────┘
                                          │
        reads (never executes) ───────────┼─────────── answers, offline by default
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
    ├─ 06  Secrets & exfiltration ...... 59 secret rules, 8 exfiltration rules, 47% of the pack
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
    └─ 17  Source, build & binaries .... build systems, binaries, licences, scan scope
```

## The one thing to remember

```
  Cordon READS. It never runs the code it is scanning, and it does not touch the
  network unless you pass --online. A scan is safe to point at hostile packages
  and safe to run in an air-gap.
```

## Install

```
  pip install cordon-scanner            # base: zero third-party runtime deps
  pip install cordon-scanner[ast-js]    # + JavaScript/TypeScript semantic rules
  pip install cordon-scanner[attest]    # + sigstore provenance verification
```

Every extra is opt-in and degrades to a *stated* limit when absent — never a
silent gap, never a crash. See tutorials 09 and 05.
