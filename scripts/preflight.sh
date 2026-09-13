#!/usr/bin/env bash
# Run the suite the way CI will, before pushing rather than after.
#
# What this covers, and what it cannot:
#
#   ubuntu x python 3.11/3.12/3.13  -- yes, in a container
#   a fresh clone, no local git state -- yes, that is the point
#   a non-UTF-8 locale               -- yes, the `UnicodeEncodeError` class
#   windows, macos                   -- NO. Those need those hosts.
#
# The CRLF and byte-order-mark classes are covered by
# `tests/integration/test_how_a_file_was_written.py`, which runs everywhere,
# so this does not try to simulate them here.
set -euo pipefail

REF="${1:-HEAD}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> exporting $REF to a clean tree (no .git, no local state)"
git -C "$REPO_ROOT" archive --format=tar "$REF" | (cd "$WORK" && tar xf -)

FAILED=0
run() {                       # run <label> <image> <extra docker args...>
  local label="$1" image="$2"; shift 2
  echo
  echo "==> $label"
  # `git` is not in the slim images, and a dozen tests need it -- the baseline
  # and VCS suites skip without it, and `test_blinding` fails rather than
  # skipping. A harness that reports failures it caused itself is worse than no
  # harness, because the next real failure gets ignored with the rest.
  # As a NORMAL user, not root. `test_blinding` chmods a file to 0o000 and
  # asserts the scan cannot read it, which is true of everybody except root --
  # and the default user in a container is root. CI runs as an ordinary user, so
  # running as root here reports failures that will never happen there.
  #
  # `git` is not in the slim images either, and a dozen tests need it: the
  # baseline and VCS suites skip without it and `test_blinding` fails outright.
  # A harness that reports failures it caused itself is worse than no harness,
  # because the next real one gets dismissed with the noise.
  if docker run --rm -v "$WORK:/src:ro" "$@" "$image" bash -c '
        set -e
        apt-get -qq update >/dev/null 2>&1
        apt-get -qq install -y --no-install-recommends git >/dev/null 2>&1
        useradd -m runner
        install -d -o runner /w && cp -a /src/. /w/ && chown -R runner /w
        su runner -c "
          set -e
          cd /w
          git init -q . && git add -A && git -c user.email=p@p -c user.name=p commit -qm base
          python -m pip install --quiet --user --upgrade pip
          pip install --quiet --user -e \".[dev]\"
          python -m pytest -q --ignore=tests/fuzz -p no:randomly
        "
      '; then
    echo "    $label OK"
  else
    echo "    $label FAILED"
    FAILED=1
  fi
}

for version in 3.11 3.12 3.13; do
  run "ubuntu / python $version" "python:${version}-slim"
done

# The locale that found the UnicodeEncodeError on Windows. `C` is the closest
# a Linux container gets to a non-UTF-8 default, and it catches the same class:
# a fixture written without an explicit encoding.
run "ubuntu / python 3.13 / LC_ALL=C" "python:3.13-slim" -e LC_ALL=C -e LANG=C -e PYTHONCOERCECLOCALE=0

echo
if [ "$FAILED" -eq 0 ]; then
  echo "preflight: all environments passed"
else
  echo "preflight: SOMETHING FAILED -- do not push"
  exit 1
fi
