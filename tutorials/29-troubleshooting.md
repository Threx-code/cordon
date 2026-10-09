# 29 · Troubleshooting

> **For Cordon 0.6.0.** Using another version? Open the tutorials at its tag: `https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` prints the link for the version you have installed.

When a scan fails, stops early, or passes where you expected a finding, Cordon has almost
always said why: in its exit code, in the scan coverage notes under the findings, or in the
hint printed under an error. This tutorial starts from what you see and works back to the
cause. Each fix is stated as Cordon states it, so the words here match the words on your
screen.

## Start from the exit code

Every run ends in one of five exit codes, and they never change meaning (`core/errors.py`).
The code says which part of this tutorial you need.

```
   ┌──────────────┐
   │ cordon-scan  │
   └──────┬───────┘
          │ exit code
          ▼
   ┌──────────────┐     ┌────────────────────────────────────────────────┐
   │ 0  clean     │────►│ nothing met the gate. Expected a finding?      │
   └──────────────┘     │ see "A scan passed that should not have"       │
   ┌──────────────┐     └────────────────────────────────────────────────┘
   │ 1  findings  │────►┌────────────────────────────────────────────────┐
   └──────────────┘     │ read them with -v; see "Findings you disagree  │
   ┌──────────────┐     │ with"                                          │
   │ 2  scanner   │     └────────────────────────────────────────────────┘
   │    error     │────►┌────────────────────────────────────────────────┐
   └──────────────┘     │ Cordon failed: see "Errors before any result"  │
   ┌──────────────┐     └────────────────────────────────────────────────┘
   │ 3  config    │────►┌────────────────────────────────────────────────┐
   │    error     │     │ a flag, file or policy is wrong: the hint      │
   └──────────────┘     │ under the error names it                       │
   ┌──────────────┐     └────────────────────────────────────────────────┘
   │ 4  incomplete│────►┌────────────────────────────────────────────────┐
   └──────────────┘     │ part of the target was not read: see "The scan │
                        │ is incomplete"                                 │
                        └────────────────────────────────────────────────┘
```

| Code | Meaning | First thing to run |
|---|---|---|
| 0 | Nothing met the failure policy | `cordon-scanner scan . --severity info` to see what sat below it |
| 1 | A finding met the failure policy | `cordon-scanner scan . -v` for the evidence and the fix |
| 2 | Cordon itself failed | rerun with `--format json`; report the error with the file named |
| 3 | A configuration problem | read the `hint:` line; `cordon-scanner config validate` |
| 4 | The scan did not read everything, and `--fail-on-incomplete` was set | read the "scan coverage" notes |

An incomplete scan is not a pass. A gate that read half a repository and said "clean" is
the failure this tool exists to prevent, so the CI templates set `--fail-on-incomplete`
and fail on 4 as well as on 1. Without the flag, as on a laptop, an incomplete scan exits
by its findings, and the coverage notes still say what was not read. Turning it off in CI
is the Action's `fail-on-incomplete: "false"`, written where reviewers can see it, for a
repository known to exceed a limit.

## The scan is incomplete

Under the findings, a scan prints `scan coverage` notes: each one is something it could not
do, and each carries its own fix. The ones met most often:

| Note | What happened | Fix |
|---|---|---|
| `OPERATIONAL.INTEL.STALE` | The threat intel is older than its limit (24 hours when Cordon can refresh it), so recent malware and advisories may not match | Let the scan reach OSV; or run `cordon-scanner advisories sync`, `cordon-scanner intel update`, or `cordon-scanner bundle install` |
| `OPERATIONAL.SCAN.TIMEOUT` | The total time budget ran out | Raise `--timeout`, or unpack an archive and scan it as a directory |
| `OPERATIONAL.FILE.TIMEOUT` | One file exceeded its budget; the malware, obfuscation, secret and binary detectors still ran on it | Raise `limits.per_file_timeout`, or exclude it if it is generated output |
| `OPERATIONAL.SCAN.MEMORY_LIMIT` | Retained content reached its budget; later files were not examined | Raise `limits.max_memory_bytes`, exclude generated or vendored directories, or scan in parts |
| `OPERATIONAL.SCAN.FINDING_LIMIT` | The finding cap was reached | Raise `limits.max_findings`; this many findings usually share one cause worth fixing first |
| `OPERATIONAL.WALK.TOO_DEEP` | A tree went deeper than `max_path_depth` | Raise `scan.limits.max_path_depth`, or scan the deep tree directly |
| `OPERATIONAL.WALK.ERROR` | Paths could not be traversed | Check permissions and path lengths |
| `OPERATIONAL.FILE.UNREADABLE` | A file could not be read | Check permissions, or exclude the path deliberately |
| `OPERATIONAL.GRAPH.LIMIT` | The dependency graph passed `max_dependencies` | Raise `limits.max_dependencies`, or scan projects separately |
| `OPERATIONAL.ARCHIVE.REJECTED` | An archive was refused by a limit | Treat it as unexamined; raise the limit deliberately if the input is legitimate |
| `OPERATIONAL.ARCHIVE.NOT_EXPANDED` | Archives were left closed | Scan without `--no-expand` |
| `OPERATIONAL.LOCKFILE.UNSUPPORTED` | A lockfile format Cordon does not read (Bun's binary `bun.lockb`) | Commit the text form beside it (`bun install --save-text-lockfile`) |
| `OPERATIONAL.LOCKFILE.UNPARSED` | A lockfile could not be parsed | Regenerate it with the package manager |
| `OPERATIONAL.MANIFEST.UNPARSED` | A manifest has a syntax error, or a construct refused on purpose (a DTD in a `.csproj`) | Fix the syntax so the manifest can be checked |
| `OPERATIONAL.PARSER.FAILED` | A parser crashed on a file | A bug: report it with the file |
| `OPERATIONAL.DETECTOR.FAILED` | A detector crashed on a file | A bug: report it with the file |
| `OPERATIONAL.FILE.LFS_POINTER` | Files are Git LFS pointers, not their content | Clone with LFS content (`actions/checkout` needs `lfs: true`) |
| `OPERATIONAL.VCS.UNREADABLE.001` | History was unavailable: usually a shallow clone | Scan where the repository is complete (`fetch-depth: 0`) |
| `OPERATIONAL.SECRET_HISTORY.INCOMPLETE.001` | The history pass stopped at a bound | Raise the bound, or scan history in its own job |
| `OPERATIONAL.IMAGE.UNREADABLE` | An image's layers could not be read | Export again with `docker save` or `skopeo copy ... oci-archive:` |
| `OPERATIONAL.IMAGE.PARTIAL` | Part of an image's OS inventory is missing | Export without zstd compression, or check the distribution is supported |
| `OPERATIONAL.IMAGE.NOT_MATCHED` | OS packages were inventoried but not matched against distribution advisories | `cordon-scanner advisories sync --os debian` (or ubuntu, alpine, wolfi, chainguard, rocky, almalinux, redhat, suse, opensuse) once, or scan with `--online` |
| `OPERATIONAL.SBOM.INVALID` | A file shaped like an SBOM could not be read | Regenerate it with its tool, or validate it against the schema |

Some notes are information, not failures: `OPERATIONAL.FILE.BINARY` (binaries are not
read as source), `OPERATIONAL.FILE.SYMLINK` (links are recorded, never followed),
`OPERATIONAL.ADVISORY.DATABASE_SCOPE` (the bundled database holds malicious and
high/critical records; `advisories sync` takes the full set) and
`OPERATIONAL.IMAGE.CONTENTS` (what an image scan covered). Every rule, these included, is
in [28 · Every rule](28-every-rule.md).

## A scan passed that should not have

Three causes cover nearly every case.

```
   ┌──────────────────────┐   ┌──────────────────────┐   ┌──────────────────────┐
   │ below the gate       │   │ not in the intel yet │   │ not read at all      │
   │                      │   │                      │   │                      │
   │ --severity info      │   │ intel: line at the   │   │ excluded, pruned,    │
   │ shows what the gate  │   │ end of the output:   │   │ gitignored with      │
   │ left out             │   │ source and age       │   │ --tracked, or in a   │
   │                      │   │                      │   │ coverage note        │
   └──────────────────────┘   └──────────────────────┘   └──────────────────────┘
```

**Below the gate.** `--fail-on high` passes a medium finding; `--severity` hides what is
below it from the report as well. Rerun with `--severity info` and the same `--fail-on` to
see the whole picture.

**Not in the intel yet.** The last lines of every scan say where the advisories came from
and how old they are:

```
intel: osv, 0h old
```

`osv` means the scan asked OSV for what changed since the bundled database was built, and
matched against that. `package` or `bundle` with a large age means it could not: an
advisory published after the database was built will not match. Cordon refreshes on its
own unless it is told not to (`--offline`, `CORDON_OFFLINE=1`, or
`CORDON_NO_ADVISORY_REFRESH=1`) or cannot reach
`osv-vulnerabilities.storage.googleapis.com`. A runner behind an egress allowlist needs
that host added; the requests name no package, so they reveal nothing about the code.

**Not read at all.** A directory in the built-in prune list (`node_modules`, `.venv`,
build output) is skipped and named in a `POLICY.COVERAGE.PRUNED` note; `--include` brings
it back. `--tracked` scans only what git tracks, so a generated or gitignored file is out
of scope. An `--exclude` that matched more than expected is reported as
`POLICY.COVERAGE.BROAD_EXCLUSION`.

## Findings you disagree with

`-v` prints, for each finding, the evidence, how its score was derived and the fix. If the
finding is wrong for your code, say so where it can be reviewed:

```
   ┌──────────────────────┐   ┌──────────────────────┐   ┌──────────────────────┐
   │ one finding          │   │ everything that      │   │ a whole class        │
   │                      │   │ exists today         │   │                      │
   │ cordon-scanner       │   │ cordon-scanner       │   │ cordon.yaml:         │
   │ suppress add         │   │ baseline create      │   │ disable the rule,    │
   │ (reason, expiry)     │   │ (adopt gradually)    │   │ under the org policy │
   └──────────────────────┘   └──────────────────────┘   └──────────────────────┘
```

A suppression carries a reason and an expiry; `suppress prune` removes the expired ones.
A baseline records what exists now so only new findings fail; `baseline compare` shows
what changed since. A rule disabled in `cordon.yaml` is refused if the organisation policy
forbids it (tutorial 14). Test fixtures are the common case: findings under a path that
holds test material are reported below their usual severity already, and a fixture
directory full of deliberate payloads belongs in `--exclude`.

A finding Cordon should not have made at all is a bug worth reporting, with the file
reduced to the smallest input that still produces it.

## Errors before any result

Exit codes 2 and 3 print a message and, usually, a `hint:` line saying what to do. The
ones met most often:

| Message | Cause | Fix |
|---|---|---|
| `unknown key(s) in cordon.yaml: ...` | A misspelt or outdated key | `cordon-scanner config validate`; the schema is in tutorial 14 |
| `organisation policy not found: ...` | `--policy` or `CORDON_POLICY` names a missing file | Point it at the file, or at the published URL with its digest |
| `policy ... does not match its pinned digest` | The policy changed after it was pinned | Fetch the published copy (`config fetch-policy`), or update the pin |
| `unknown detector(s): ...` | A `--detector` name that does not exist | The message lists the available ones |
| `unknown output format ...` | A `--format` that does not exist | `text`, `json`, `sarif`, `junit`, `markdown`, `github`, `codeclimate`, `vex` |
| `target does not exist: ...` | The path is wrong for the working directory | In CI, check the job's working directory |
| `CORDON_OFFLINE is set, so the feed will not be fetched` | `intel update` with the network turned off | Unset it for the update, or install a bundle |

`cordon-scanner config explain` prints the configuration in effect once the command line,
`cordon.yaml` and the organisation policy are combined, with its hash: two runs with the
same hash were configured the same.

## Works locally, fails in CI

The runner is not your laptop. The differences that matter:

| Difference | Symptom | Fix |
|---|---|---|
| Shallow checkout | `OPERATIONAL.VCS.UNREADABLE.001`; `--history` reads nothing | `fetch-depth: 0` (GitHub), `GIT_DEPTH: 0` (GitLab), `clone: depth: full` (Bitbucket) |
| LFS content not fetched | `OPERATIONAL.FILE.LFS_POINTER` | `lfs: true` on checkout |
| No network, or an allowlist | `OPERATIONAL.INTEL.STALE`; `intel: package` | Allow `osv-vulnerabilities.storage.googleapis.com`, or ship a signed bundle (tutorial 11) |
| A slower machine | `OPERATIONAL.SCAN.TIMEOUT` | Raise `--timeout`; scan in parts |
| Windows line endings | Fewer dependencies than locally | 0.6.0 reads CRLF the same as LF; on an older version set `core.autocrlf false` for the checkout |
| A different cache | Results differ between runs | `--no-cache` to compare: a cached result is reused only under the same configuration |
| A different scanner version | New or missing findings | Pin `CORDON_VERSION`; read the CHANGELOG for the version that changed |

## Per CI system

Every template installs the scanner from PyPI with `--require-hashes`, against the hash pin
committed at the release tag (`action/requirements.txt` at `v<version>`). An install that
fails on a hash is the template refusing an artefact it cannot verify, which is what it is
for.

### GitHub Actions

```yaml
permissions:
  contents: read
  security-events: write    # SARIF upload; without it the upload step fails
  id-token: write           # only for Cordon Cloud upload
steps:
  - uses: actions/checkout@<sha>
    with:
      fetch-depth: 0        # only if you scan --history
  - uses: Threx-code/cordon/action@v0.6.0
```

| Symptom | Cause | Fix |
|---|---|---|
| `CORDON_VERSION is X, but this ref pins a different version` | `CORDON_VERSION` disagrees with the Action's ref | Point `uses:` at the tag for that version, or unset `CORDON_VERSION` |
| `This ref of the Action carries no hash pin, so the download cannot be verified.` | A ref (a branch, an old SHA) without `action/requirements.txt` | Point `uses:` at a release tag; `allow-unverified-install: true` only for a ref that predates signed releases |
| `Resource not accessible by integration` on SARIF upload | `security-events: write` missing | Add it to the job's `permissions` |
| Fails on a pull request from a fork | A fork's token cannot write security events or mint an ID token | Skip the upload on forks: `if: github.event.pull_request.head.repo.fork == false` |
| Fails, nothing in the findings | Exit 4 under `fail-on-incomplete: true` (the default) | Read the coverage notes in the step log |

### GitLab CI

`ci/gitlab/cordon.gitlab-ci.yml` reads `CORDON_VERSION`, `CORDON_SEVERITY`,
`CORDON_FAIL_ON`, `CORDON_OFFLINE` and `CORDON_UPLOAD`. `CORDON_VERSION is not a version`
means it is not `X.Y.Z`. The pin is fetched from `raw.githubusercontent.com`; a runner that
cannot reach it fails before installing, and needs that host allowed or the pin vendored.
Cloud upload uses the job's `id_tokens` (`CORDON_ID_TOKEN`).

### Bitbucket Pipelines

The pipe takes `SEVERITY`, `FAIL_ON` and `UPLOAD` as `variables:`, and reads
`BITBUCKET_CLONE_DIR`. Upload needs `oidc: true` on the step, which provides
`BITBUCKET_STEP_OIDC_TOKEN`. History needs `clone: depth: full`.

### Azure Pipelines, CircleCI, Buildkite, Jenkins

Each reads `CORDON_VERSION`, `CORDON_SEVERITY`, `CORDON_FAIL_ON` and `CORDON_UPLOAD`.
Upload uses the platform's identity token (`CORDON_ID_TOKEN`); Azure, CircleCI and
Buildkite also need `CORDON_ORGANIZATION`, and Azure a service connection in
`CORDON_SERVICE_CONNECTION`. The templates are `ci/azure/cordon-task.yml`,
`ci/circleci/orb.yml`, `ci/buildkite/pipeline.yml` and `ci/jenkins/vars/cordonScan.groovy`;
the gate they implement is tutorial 10's.

### Anything else

`ci/generic/scan.sh` runs the published image (`CORDON_IMAGE`) with Docker, honouring
`CORDON_FAIL_ON` and `CORDON_OFFLINE`. If Docker is not available on the runner, install
the scanner with the hash pin instead, as the templates do.

## Git hooks

```
   ┌──────────────┐    ┌──────────────┐    ┌──────────────────────────────┐
   │ git commit / │───►│ hook runs    │───►│ blocked: findings, or        │
   │ git push     │    │ cordon scan  │    │ a guard that was changed     │
   └──────────────┘    └──────────────┘    └──────────────────────────────┘
```

| Symptom | Cause | Fix |
|---|---|---|
| `tampered: <file> does not match the manifest` | A guarded file (a workflow that runs the scanner, the policy, a baseline) changed | If intended, `cordon-scanner guard update`, and have the manifest diff reviewed with it |
| The hook does not run at all | Not installed, or `core.hooksPath` points elsewhere | `cordon-scanner guard install`; `git config core.hooksPath` |
| The hook is slow | It scans more than the change | Hooks scan staged files (`--staged`); a full scan belongs in CI |

`git commit --no-verify` skips a hook. It is sometimes right, and always visible in
review: the CI gate runs the same scan regardless.

## Container images

| Symptom | Fix |
|---|---|
| `OPERATIONAL.IMAGE.UNREADABLE` | Export with `docker save -o image.tar <image>`, then scan the tar |
| OS packages listed, none matched (`OPERATIONAL.IMAGE.NOT_MATCHED`) | `cordon-scanner advisories sync --os <family>` once, then scan offline |
| A language package you expected is missing | Images list what is installed: a lockfile in the image counts only where its packages are installed |
| The scan runs out of memory on a very large image | Scan it on a machine with more memory, or raise `limits.max_memory_bytes` deliberately |

## Slow scans

| Cause | Fix |
|---|---|
| A large monorepo | `--jobs` for more workers; the cache makes the second run incremental |
| Vendored or generated trees | `--exclude` them, deliberately and visibly |
| Large archives | They are opened and scanned; `--no-expand` trades coverage for speed, and says so |
| Every scan on a fresh runner | Cache the directory in `CORDON_CACHE_DIR` between runs |
| Network checks | `--online` asks registries; leave it for scheduled jobs if pull requests must be fast |

## Asking for help

A report that can be acted on has the version, the command, and the JSON result:

```bash
cordon-scanner --version
cordon-scanner scan . -v --format json:result.json --audit-log audit.jsonl
```

`result.json` holds every finding, coverage note and the intel status; the audit log
records what the scan did. Both name paths in the repository and nothing else. For a crash
(exit 2), the smallest file that reproduces it is worth more than any description.

Next: back to **[the tutorial map](README.md)**.
