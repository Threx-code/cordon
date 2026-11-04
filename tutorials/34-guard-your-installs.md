# 34 · Guard your installs: pnpm, npm and pip

> **For Cordon 0.7.0.** Using another version? Open the tutorials at its tag: `https://github.com/Threx-code/cordon/tree/v<version>/tutorials`. `cordon-scanner --help` prints the link for the version you have installed.

The moment a package is most dangerous is the install: `postinstall`, `setup.py` and build
backends run with your user's rights before anyone has read a line. Your package manager's
own audit runs *after* resolution and knows only what an advisory already says. Cordon can
stand in front of it as a second guard, so nothing new is installed until it has been read.

```
┌──────────────────────────────────────────────────────────────────────────┐
│  WITHOUT A GUARD                                                         │
│    pnpm add pkg ──► resolve ──► download ──► install scripts RUN ──► audit│
│                                                   ▲                      │
│                                          the payload runs here           │
│                                                                          │
│  WITH CORDON IN FRONT                                                    │
│    1 resolve only ── the lockfile changes; nothing downloaded to run     │
│    2 Cordon reads what the lockfile would bring in                       │
│         known malicious · known vulnerable · (with --online) the code    │
│    3 pass ──► install exactly what was checked (frozen lockfile)         │
│      fail ──► package.json and the lockfile are put back as they were    │
└──────────────────────────────────────────────────────────────────────────┘
```

Two guards follow, one for the JavaScript package managers and one for pip, then the same
check in CI, where it matters most.

## pnpm and npm: `cordon-add`

Save this as `cordon-add` somewhere on your `PATH` (for example `~/.local/bin/cordon-add`)
and make it executable with `chmod +x`. It needs `cordon-scanner`, git, and the project to be
a git repository (it compares with `HEAD`).

```bash
#!/usr/bin/env bash
# cordon-add: add packages the way you always do, but resolve first, let Cordon read
# what the lockfile would bring in, and only then install. Nothing is downloaded to run
# until the check passes.
#
#   cordon-add pnpm left-pad@1.3.0        cordon-add npm left-pad@1.3.0
#
# CORDON_ONLINE=1 also fetches each new release from its registry and reads its code.
set -euo pipefail
pm="${1:?usage: cordon-add pnpm|npm <package>...}"; shift
[ "$#" -gt 0 ] || { echo "cordon-add: name at least one package" >&2; exit 2; }
online=(); [ "${CORDON_ONLINE:-0}" = 1 ] && online=(--online)

case "$pm" in
  pnpm) lock=pnpm-lock.yaml;    resolve=(pnpm add --lockfile-only "$@");                     install=(pnpm install --frozen-lockfile) ;;
  npm)  lock=package-lock.json; resolve=(npm install --package-lock-only --ignore-scripts "$@"); install=(npm ci) ;;
  *)    echo "cordon-add: $pm is not pnpm or npm" >&2; exit 2 ;;
esac

backup=$(mktemp -d)
cp package.json "$backup/"; [ -f "$lock" ] && cp "$lock" "$backup/"
restore() { cp "$backup/package.json" .; if [ -f "$backup/$lock" ]; then cp "$backup/$lock" .; else rm -f "$lock"; fi; }

"${resolve[@]}"                          # the lockfile only: nothing in node_modules, nothing run
if ! cordon-scanner review --base HEAD "${online[@]}"; then
  restore
  echo "cordon-add: refused; package.json and $lock are as they were" >&2
  exit 1
fi
"${install[@]}"                          # exactly what was checked
```

Use it in place of `pnpm add` or `npm install <pkg>`:

```
$ cordon-add pnpm lodash@4.17.20
1 dependency change(s) since HEAD

added      npm:lodash 4.17.20 (direct)  BLOCKING
    vulnerable: GHSA-35jh-r3h4-6jhm (high)
    vulnerable: GHSA-r5fr-rjxr-66jc (high)
cordon-add: refused; package.json and pnpm-lock.yaml are as they were

$ cordon-add pnpm left-pad@1.3.0
1 dependency change(s) since HEAD

added      npm:left-pad 1.3.0 (direct)
+ left-pad 1.3.0
```

A release the malicious-package records list is refused the same way, as `known malicious:
MAL-…`, and so is every package it pulls in transitively: `review` compares the whole
resolved graph, not just the name you typed.

```
   cordon-add pnpm pkg                 offline: the advisory and malicious-package records,
                                       seconds
   CORDON_ONLINE=1 cordon-add pnpm pkg each new release is also fetched from npm, its
                                       digest verified, and its code read (about a minute
                                       for a small package)
```

### Why each step is there

```
   pnpm add --lockfile-only    resolves and writes pnpm-lock.yaml; no node_modules,
                               so no install script can run yet
   npm install                 the same for npm; --ignore-scripts keeps it that way
     --package-lock-only
   review --base HEAD          the graph before and after: added, upgraded, downgraded,
                               removed, each with what it brings (tutorial 21)
   --frozen-lockfile / npm ci  installs the lockfile as checked, and fails rather than
                               resolving anything new
```

## pip: `cordon-pip`

pip has no resolve-only mode, and an sdist runs its build backend just to report its own
metadata, so even `pip download` of an sdist runs the package's code. The guard downloads
**wheels only**, reads them, and installs from that folder with the index switched off, so
what is installed is byte for byte what was read.

```bash
#!/usr/bin/env bash
# cordon-pip: install Python requirements only after Cordon has read the exact files pip
# would install. Wheels only: an sdist runs its build backend just to report its metadata,
# so a download alone would already run the package's code.
#
#   cordon-pip -r requirements.txt        cordon-pip requests==2.32.3
set -euo pipefail
[ "$#" -gt 0 ] || { echo "usage: cordon-pip -r requirements.txt | <requirement>..." >&2; exit 2; }
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT

python -m pip download --only-binary=:all: --dest "$dir" "$@"     # dependencies included
cordon-scanner scan "$dir" --fail-on high --fail-on-incomplete
python -m pip install --no-index --find-links "$dir" "$@"         # only what was read
```

```
$ cordon-pip requests==2.32.3
Successfully downloaded requests certifi charset-normalizer idna urllib3
0 critical · 0 high · 0 medium · 2 low
scan complete
Successfully installed certifi-2026.10.23 charset-normalizer-3.5.2 idna-3.20 requests-2.32.3 urllib3-2.8.0
```

Each wheel is read for what its code does, and its own name and version are matched against
the malicious-package records and the vulnerability advisories. A requirement that is only
published as an sdist stops at the download with `Could not find a version that satisfies
the requirement`: build that one yourself, in a container, after reading it
(`cordon-scanner scan pkg:pypi/<name>@<version> --online`).

## In CI: the same check on every pull request

A guard on one laptop protects one laptop. The pipeline is where every change to a lockfile
passes, so check it there before anything is installed:

```yaml
# GitHub Actions: the scan and the dependency review run before anything is installed
steps:
  - uses: actions/checkout@v4
  - uses: Threx-code/cordon/action@v0.7.0
    with:
      fail-on: high
      dependency-review: "true"          # on a pull request: what the lockfile change adds
  - run: pnpm install --frozen-lockfile  # reached only when both passed
```

The scan reads the whole tree, lockfiles included, so a dependency that slipped in without a
guard is still caught before `install`; the dependency review fails the job for a
known-malicious or high or critical release the pull request adds. Tutorial 35 builds this
into a complete workflow, and 36 and 37 do the same for the other CI systems.

Next: **[35 · GitHub Actions](35-github-actions.md)**.
