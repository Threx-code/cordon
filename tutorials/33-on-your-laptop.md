# 33 · On your laptop

> **For Cordon 0.7.0.** Using another version? Open the tutorials at its tag: `https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` prints the link for the version you have installed.

Level 1, one machine: install Cordon once, check a package before it is installed, scan
the project you are working on, and put a hook in git so a commit that adds something
hostile never lands. Each step works on its own; together they cover what reaches the
laptop and what leaves it.

```
┌──────────────────────────────────────────────────────────────────────────┐
│   a package you are about to add ──► 1  vet it ── pass ──► install it    │
│                                                                          │
│   the project you work on ─────────► 2  scan it ── on demand, any time   │
│                                                                          │
│   every git commit ────────────────► 3  hook scans what is staged        │
│                                         fails closed: a broken or        │
│                                         missing scanner blocks the       │
│                                         commit instead of waving it on   │
└──────────────────────────────────────────────────────────────────────────┘
```

## Install

Cordon has no third-party runtime dependencies. Install it in an environment of its own so
the projects you scan can never change it:

```bash
pipx install cordon-scanner          # or: uv tool install cordon-scanner
cordon-scanner --version
cordon-scanner verify                # the installation checked against its own RECORD
```

It runs on Python 3.11 to 3.15. `verify` exits 4 rather than 0 offline: it can say the
files match their RECORD, but whoever can edit the files can edit the RECORD too, so it
never claims more than that (`cordon-scanner help verify` lists every exit code).

## 1 · Vet a package before you install it

Give `scan` a package URL and `--online`: Cordon fetches that release from its own registry,
checks its digest, and reads it. Nothing is installed and nothing runs.

```bash
cordon-scanner scan pkg:npm/left-pad@1.3.0 --online
cordon-scanner scan pkg:pypi/requests@2.32.3 --online
cordon-scanner scan pkg:docker/nginx@1.27 --online
```

```
   exit 0  nothing at or above the gate: install it
   exit 1  read the findings first (add -v for the evidence and the fix)
   exit 4  something could not be read: treat it as not checked
```

A file you already downloaded is scanned the same way, offline:

```bash
cordon-scanner scan ./left-pad-1.3.0.tgz --offline
```

## 2 · Scan the project you are working on

```bash
cordon-scanner scan .                       # the whole tree
cordon-scanner scan . --git-diff origin/main  # only what your branch changed
cordon-scanner deps .                         # the dependency graph and each package's verdict
```

`--fail-on` sets the gate for the exit code (`critical`, `high`, `medium` or `low`;
`high` by default), and `-v` shows, for each finding, the evidence, how its score was
derived and what to do about it.

## 3 · Git hooks that fail closed

```bash
cordon-scanner guard install            # this repository
cordon-scanner guard install --global   # every repository you clone or create from now on
cordon-scanner guard verify             # are the hooks still intact?
```

```
┌──────────────────────────────────────────────────────────────────────────┐
│  git commit                                                              │
│      │                                                                   │
│      ▼                                                                   │
│  pre-commit ──► cordon-scanner scan --staged ── exit 0 ──► commit lands  │
│      │                                                                   │
│      └── a finding, an unreadable file, or no scanner at all            │
│              ──► the commit is refused, and the reason is printed        │
└──────────────────────────────────────────────────────────────────────────┘
```

The hooks scan only what is staged, so they take seconds. `--global` also checks what
`clone`, `checkout` and `pull` bring in before it lands in the working tree (tutorial 22).
A hook that is edited or removed is reported by `guard verify`; `guard update` records the
hooks again after you change them on purpose.

## Keep the intel current

Every scan asks OSV for advisories published since this release, so new advisories reach
you without an upgrade. Without that, or the signed feed, intel older than a week makes
the scan incomplete rather than quietly out of date. On a machine that is often offline:

```bash
cordon-scanner advisories sync     # the full advisory database, into your cache
cordon-scanner intel status        # where the intel came from, and how old it is
```

Next: **[34 · Guard your installs](34-guard-your-installs.md)**.
