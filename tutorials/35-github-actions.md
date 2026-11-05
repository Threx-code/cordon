# 35 · GitHub Actions, from one step to a full workflow

> **For Cordon 0.7.0.** Using another version? Open the tutorials at its tag: `https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` prints the link for the version you have installed.

Level 2, every repository's pipeline. The Cordon action installs the scanner (checked
against the hash pinned in the action), scans, writes SARIF for code scanning and a summary
for the job, and fails the job on your gate. Each step below adds to the one before; copy
whichever level you need into `.github/workflows/cordon.yml`.

```
┌──────────────────────────────────────────────────────────────────────────┐
│  pull request / push                                                     │
│      │                                                                   │
│      ▼                                                                   │
│  install cordon-scanner ── checked against the action's pinned hash      │
│      │                                                                   │
│      ▼                                                                   │
│  scan ──► job summary ──► SARIF ──► Security tab, findings on the lines  │
│      │                                                                   │
│      ├── dependency review (pull requests): what the lockfile change adds│
│      │                                                                   │
│      ▼                                                                   │
│  exit 0 pass · 1 findings at fail-on · 2/3 error · 4 incomplete          │
└──────────────────────────────────────────────────────────────────────────┘
```

## Level 1: scan every push and pull request

```yaml
name: cordon
on: [push, pull_request]

permissions:
  contents: read           # checkout
  security-events: write   # SARIF upload to code scanning

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Threx-code/cordon/action@v0.7.0
```

The defaults are the safe ones: `fail-on: high`, `fail-on-incomplete: true` (a scan that
could not read everything has not passed), `sarif: true`, and secret evidence hashed. The
action refuses to run under `pull_request_target`, which hands a writable token and the
repository's secrets to a job that may check out untrusted code.

## Level 2: review every dependency change on the pull request

```yaml
permissions:
  contents: read
  security-events: write
  pull-requests: write     # only for the comment

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Threx-code/cordon/action@v0.7.0
        with:
          dependency-review: "true"           # added · upgraded · downgraded · removed
          dependency-review-online: "true"    # fetch, verify and compare each changed release
          dependency-review-comment: "true"   # one comment, updated on every push
```

```
   pull request bumps the lockfile
        │
        ├─► scan        the whole tree; the gate
        └─► review      the graph at the base commit vs this branch
                         known malicious or high/critical ─► job fails
                         with --online: new install hooks, capabilities,
                         binaries and a new publisher, release by release
```

The base commit is fetched by its id and passed through the environment, never written into
a script, because a branch name is chosen by whoever opens the pull request. Tutorial 21
explains the review in full.

## Level 3: thresholds per trigger, and a nightly sweep

```yaml
name: cordon
on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: "17 3 * * *"     # nightly: new advisories against code nobody touched

permissions:
  contents: read
  security-events: write

jobs:
  gate:
    if: github.event_name != 'schedule'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Threx-code/cordon/action@v0.7.0
        with:
          fail-on: high
          dependency-review: "true"

  nightly:
    if: github.event_name == 'schedule'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Threx-code/cordon/action@v0.7.0
        id: cordon
        continue-on-error: true      # makes the backlog visible without blocking anyone
        with:
          fail-on: medium
      - if: steps.cordon.outputs.findings != '0'
        run: echo "::warning::${{ steps.cordon.outputs.findings }} findings at medium or above"
```

| Where | `fail-on` | Why |
|---|---|---|
| Pull request | `high` | the gate that holds the line |
| Push to main | `high` | the same gate after merge |
| Nightly | `medium`, non-blocking | an advisory published today, against code unchanged for a month |
| Release | `high`, `fail-on-incomplete: "true"` | the one place a partial scan must never pass |

## Level 4: a release that proves its own scanner

```yaml
  release-gate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: Threx-code/cordon/action@v0.7.0
        with:
          verify-install: "true"      # the wheel's PyPI provenance, signed by Cordon's release
                                      # workflow, and every installed file against it
          fail-on: high
          fail-on-incomplete: "true"
          policy: .github/cordon-policy.yaml   # the organisation's ceiling (tutorial 39)
```

## Level 5: send results to Cordon Cloud

```yaml
permissions:
  contents: read
  security-events: write
  id-token: write              # the job's own OIDC identity; no secret is stored

steps:
  - uses: actions/checkout@v4
  - uses: Threx-code/cordon/action@v0.7.0
    with:
      upload: "true"
      cloud-url: https://core-api.cordonscan.com   # a fixed value, never from github.event
```

The job exchanges its OIDC token for a fifteen-minute Cordon token. An organisation admin
adds a trust rule for the repository first. A scan of the default branch can close findings
that are fixed.

## Every input

| Input | Default | What it does |
|---|---|---|
| `target` | `.` | path or archive to scan |
| `working-directory` | `.` | where to run |
| `config` | discovered | the repository's `cordon.yaml` |
| `policy` | none | an organisation policy: a ceiling the repository cannot lower |
| `severity` | `low` | report findings at or above |
| `fail-on` | `high` | fail the job at or above |
| `fail-on-incomplete` | `true` | a scan that did not read everything fails |
| `sarif` / `sarif-file` | `true` / `cordon.sarif` | code scanning upload |
| `evidence` | `masked` | `none`, `masked` or `hash_only`; secrets are always hashed |
| `dependency-review` | `false` | the pull request's dependency changes |
| `dependency-review-online` | `false` | fetch and compare each changed release |
| `dependency-review-comment` | `false` | post the review as a comment |
| `verify-install` | `false` | check the scanner against its signed release |
| `upload` / `cloud-url` | `false` | send results to Cordon Cloud |

Outputs: `findings` (how many met the gate), `sarif-file`, and `complete`.

## Pin it

A tag can be moved; a commit cannot. Pin the action by its full commit id with the version
as a comment; the `ci/github/cordon-pin-bump.yml` workflow (tutorial 24) keeps it current
with a pull request per new release:

```yaml
      - uses: Threx-code/cordon/action@<40-character commit id>   # v0.7.0
```

Next: **[36 · GitLab CI](36-gitlab-ci.md)**.
