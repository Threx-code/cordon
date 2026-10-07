# 21 · Reviewing a dependency update

> **For Cordon 0.6.0.** Using another version? Open the tutorials at its tag: `https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` prints the link for the version you have installed.

A pull request that bumps a lockfile is reviewed as a diff nobody reads: hundreds of
changed `integrity` lines, and somewhere among them the one package that started running
code at install. `review` reads the dependency graph twice and shows the difference a
reviewer actually has to judge.

```
┌──────────────────────────────────────────────────────────────────────────┐
│   base revision (from git)              working tree (this branch)       │
│   ┌──────────────────────┐              ┌──────────────────────┐         │
│   │ lockfiles, manifests │              │ lockfiles, manifests │         │
│   └──────────┬───────────┘              └──────────┬───────────┘         │
│              └──────────── graph diff ─────────────┘                     │
│                                │                                         │
│      added · upgraded · downgraded · removed, each with what it brings   │
└──────────────────────────────────────────────────────────────────────────┘
```

## Run it

```
   cordon-scanner review --base origin/main
   cordon-scanner review --base origin/main --online       # also compare releases
   cordon-scanner review --base origin/main --format markdown > review.md
```

## What it reports

```
┌──────────────────────────────────────────────────────────────────────────┐
│  OFFLINE, for every added, upgraded or downgraded package                │
│    known-malicious records that match the new version                    │
│    known vulnerabilities it brings in, and the ones the update fixes     │
│                                                                          │
│  WITH --online, each changed package's old and new releases are          │
│    fetched from its own registry   npm  PyPI  crates.io  RubyGems        │
│                                    NuGet  Go proxy  Hex  pub  Maven      │
│    verified against the digest     (Go: the checksum database's h1:)     │
│    the registry publishes                                                │
│    scanned, never installed or run                                       │
│    compared like tutorial 19       new install hook · new capability     │
│                                    new obfuscation · new binary          │
└──────────────────────────────────────────────────────────────────────────┘
```

Nothing is fetched that cannot be verified: Packagist publishes no archive digest, so a
Composer package is listed and said not to be compared.

## Exit codes

```
   0   nothing in the update needs stopping
   1   the update brings in a known-malicious release, a known vulnerability at
       high or critical, or a release that gained an install hook or a decisive
       capability
```

## On every pull request

The GitHub Action runs it after the scan, with the base branch's commit as `--base`:

```yaml
- uses: Threx-code/cordon/action@<sha>   # v0.6.0
  with:
    dependency-review: true          # the report, in the job summary
    dependency-review-online: true   # fetch, verify and compare each release
    dependency-review-comment: true  # and as a PR comment (pull-requests: write)
```

The base commit reaches the step through the environment, never interpolated into the
script: a branch name is chosen by whoever opened the pull request.

Next: **[22 · Code arriving from someone else](22-incoming-code.md)**.
