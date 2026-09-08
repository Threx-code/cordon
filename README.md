# Cordon

**A language-agnostic software supply-chain security scanner.**

Cordon inspects source code, dependency manifests, lockfiles, build scripts,
CI configuration, containers and infrastructure-as-code for malicious packages,
suspicious install-time behaviour, leaked credentials and dependency risk. It
runs identically on a developer laptop, in a pre-commit hook, in any CI system,
and inside an air-gapped enterprise network.

```bash
pipx install cordon-scanner
cordon scan .
```

---

## Why this exists

Most security scanning answers the question *"does the code I wrote contain a
bug?"* That question is well served. SAST tools, linters and CVE databases have
been mature for a decade.

Cordon answers a different question: **"is the code I did not write trying to
attack me?"**

That distinction matters because of where modern software actually comes from.
A typical application is a few thousand lines of first-party code sitting on top
of a few hundred thousand lines of third-party code, pulled from a public
registry, resolved transitively, and — critically — **executed on the
developer's machine at install time**, before any test runs, any review happens,
or any container boundary exists.

### The attack that this class of tool exists to stop

The supply-chain attack pattern is now well established and repeats with small
variations:

1. An attacker gains publish rights to a package, through a phished maintainer
   account, an expired domain on a maintainer's email, an abandoned package
   handed over to a volunteer, or a typosquatted name nobody was watching.
2. They publish a version that is functionally identical to the last one, plus a
   lifecycle script — `postinstall`, `prepare`, a `build.rs`, a `setup.py`
   command class, a Gradle task.
3. That script runs as the developer, with the developer's environment: SSH
   keys, cloud credentials, npm and PyPI publish tokens, browser profiles,
   sometimes cryptocurrency wallets.
4. It reads what it can reach, encodes it, and sends it somewhere.
5. Increasingly, it also propagates: it uses the credentials it stole to publish
   a poisoned version of every package the compromised developer maintains.

The whole exchange takes place in the seconds between typing an install command
and getting a prompt back. There is no code review step. There is no CI gate.
There is no runtime sandbox. By the time anything else in the pipeline could
have an opinion, the payload has already run.

This is not a hypothetical threat model. It is the documented shape of
`event-stream`, `ua-parser-js`, `coa`, `rc`, `node-ipc`, the `torchtriton`
dependency-confusion incident, the `xz-utils` backdoor, and the self-replicating
npm worms of 2025.

### Why existing tools do not cover it

The tools most teams already run are good at what they do and structurally
cannot cover this:

| Tool class | What it answers | Why it misses this |
|---|---|---|
| CVE/advisory scanners (`npm audit`, `pip-audit`, Dependabot) | "Does a dependency have a *published advisory*?" | A malicious package published an hour ago has no advisory. By the time one exists, the payload has run. |
| SAST (Semgrep, Bandit, CodeQL) | "Does *my* code have a vulnerability?" | Points at first-party code. Dependencies and lockfiles are out of scope by design. |
| Secret scanners (gitleaks, trufflehog) | "Did someone commit a credential?" | Finds credentials at rest, not code that harvests them at runtime. |
| Container scanners (Trivy, Grype) | "Does this image have vulnerable OS packages?" | Scans the built image. The compromise happened during the build. |
| Linters | "Is this code well-formed?" | Not a security control. |

Every one of these is worth running. None of them is looking at the specific
moment where the supply-chain attack lands: **a package's own code, doing
something it has no business doing, at install or build time.**

### Why it has to be this large

A narrow tool would be easy to build and would not work. The scope is set by the
problem, not by ambition:

- **It must be language-agnostic**, because supply-chain attacks are not.
  A scanner that only understands JavaScript is blind on a Python service, and
  most organisations are polyglot. The detection model therefore has to be
  built on capability primitives that generalise, with per-language patterns as
  data.

- **It must understand package ecosystems**, not just files. A malicious
  dependency six levels deep in a lockfile does not appear in any diff and is not
  present in any file the developer wrote. Finding it means parsing lockfiles for
  eleven ecosystems and building a real dependency graph.

- **It must distinguish four different kinds of claim.** A CVE in a dev
  dependency, an obfuscated blob in a config file, a credential harvester in a
  postinstall hook, and an unpinned version are four different problems with four
  different owners and four different urgencies. A tool that reports them
  identically gets configured away.

- **It must control false positives aggressively.** This is the requirement that
  determines adoption. A security tool that cries wolf is a security tool that
  gets a `|| true` appended to it, and that is worse than not having it. Hence
  independent severity and confidence, corpus-validated rules, expiring
  suppressions, baselines, and an explainable score.

- **It must be fast enough to run on every commit.** A pre-commit guard that
  takes thirty seconds is bypassed within a week, and a bypassed guard is worth
  nothing. Speed is a security property here, not a convenience.

- **It must be hardened against what it scans.** It is pointed, deliberately, at
  code that may be actively hostile, on machines holding production credentials.
  Zip bombs, path traversal, symlink escapes and catastrophic regex backtracking
  are all ordinary inputs from its perspective.

- **It must not become the next incident.** A security tool sits in privileged
  positions on every developer machine and every CI runner in an organisation.
  Cordon's core therefore has **zero third-party runtime dependencies**, executes
  nothing from the code it scans, and makes no network request unless explicitly
  told to.

---

## Design principles

These are constraints, not preferences. Everything in the architecture follows
from them.

1. **The scan target is untrusted input.** Every byte of it, including its own
   configuration file.
2. **Never execute the code being analysed.** Manifests are parsed, never
   imported, evaluated, or handed to the ecosystem's own tooling.
3. **Offline by default.** Advisory data ships as a local database. Network
   access is an explicit flag that logs every host it contacts.
4. **Zero runtime dependencies in the core.** One wheel, nothing transitive,
   an SBOM a human can read.
5. **Deterministic.** Identical inputs produce byte-identical output, in a
   stable order. This is what makes baselines, caching and reproducible gates
   possible.
6. **Findings never leak what they found.** Evidence is redacted by default;
   secret findings carry a hash, never the secret.
7. **Explainable.** Every finding shows the rule that fired and every factor that
   contributed to its score. A score nobody can reconstruct is a score nobody
   trusts.
8. **Rules are versioned, testable data** — not lines of engine code. Every rule
   ships with samples proving it fires and samples proving it does not overfire.

---

## What it looks like

```
CRITICAL  MALWARE.EXFIL.001                                    risk 92/100
  package.json:14  .  scripts.postinstall
  confidence: high  .  category: malicious  .  detector: manifest

  The postinstall script reads environment variables and pipes them to a
  remote host. This executes as your user on every install, before any
  other control.

  evidence   scripts.postinstall = "node -e '...env...' | curl -X POST [redacted]"
             match sha256:4b1f2e8a...

  why        CREDENTIAL  process.env read              +12
             EGRESS      request to a non-registry host +10
             CONTEXT     runs during install            +15
             base(CRITICAL) 90 x 1.00(high) = 90, clamped to 92

  fix        Remove the postinstall script. If a build step is genuinely
             required, move it to an explicit, reviewed build command.
```

---

## Usage

### CLI

```bash
cordon scan .                              # scan a directory
cordon scan ./package.tar.gz               # scan an archive
cordon scan --staged                       # scan staged content (pre-commit)
cordon scan --git-diff origin/main         # scan only what changed
cordon scan --tracked                      # skip build output and ignored paths

cordon scan --format sarif:cordon.sarif    # CI-friendly output
cordon scan --severity high --fail-on high # gate a pipeline
cordon inventory .                         # what is this repository?
cordon rules list                          # what will run
cordon config validate                     # check configuration

cordon baseline create                     # record today's findings as known debt
cordon scan --baseline cordon-baseline.json  # existing debt marked, new findings fail
cordon baseline compare                    # fail only on what is new
```

Every command above exists. `docs/03-INTERFACES.md` also describes commands that
are designed but not yet implemented, and says which is which.

Exit codes: `0` clean, `1` findings met the failure policy, `2` scanner error,
`3` configuration error, `4` scan incomplete.

### SDK

```python
from cordon import Scanner, Config

scanner = Scanner(Config.from_file("cordon.yaml"))
result = scanner.scan("./repository")

for finding in result.findings:
    print(finding.rule_id, finding.severity, finding.location)
```

### GitHub Action

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v4
  - uses: cordon-dev/cordon-action@v1
    with:
      severity: high
      sarif: true
```

---

## Documentation

| Document | Contents |
|---|---|
| [`docs/01-ARCHITECTURE.md`](docs/01-ARCHITECTURE.md) | Engine, detection model, plugin system, rule engine, repository and dependency analysis |
| [`docs/02-THREAT-MODEL.md`](docs/02-THREAT-MODEL.md) | Trust boundaries, threats against the scanner itself, and what Cordon explicitly does not defend against |
| [`docs/03-INTERFACES.md`](docs/03-INTERFACES.md) | CLI, SDK, GitHub Action, CI integration, configuration, SARIF |
| [`docs/04-OPERATIONS.md`](docs/04-OPERATIONS.md) | Performance, testing, enterprise deployment, roadmap |

---

## Status

Early development. See the roadmap in
[`docs/04-OPERATIONS.md`](docs/04-OPERATIONS.md).

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
