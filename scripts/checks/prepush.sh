#!/bin/sh
# What CI will say about the commit being pushed, said before it is pushed.
#
#   scripts/checks/prepush.sh           everything CI runs, the full suite included (about 15 minutes)
#   scripts/checks/prepush.sh --quick   everything but the suite, perf and fuzz (about 5 minutes)
#
#   CORDON_PREPUSH_MEMORY=16g scripts/checks/prepush.sh   the container's memory cap (default 10g)
#   CORDON_PREPUSH_WORKERS=4 scripts/checks/prepush.sh    the suite's pytest workers (default 8)
#
# The run ends by printing the container's peak memory and its count of processes the cap killed.
# Any kill fails the run as "killed by the memory cap", whatever the tests reported, so a cap kill
# never passes for a flaky test.
#
# Installed as the pre-push hook by `make hooks`. Nothing runs on the host but git and the
# Docker CLI: the checks run in a container, against a clean clone of HEAD, so the working
# tree's uncommitted and gitignored files neither help nor hurt. See scripts/checks/ci_parity.py for
# what runs, and scripts/checks/portability.py for the checks aimed at Windows and macOS.
#
# A push that must go out with this failing is `git push --no-verify`, and the failure is then
# CI's to report.
set -eu

root=$(git rev-parse --show-toplevel)
mode=""
[ "${1:-}" = "--quick" ] && mode="--quick"

command -v docker >/dev/null 2>&1 || { echo "prepush: Docker is required" >&2; exit 2; }

# A cap on the container's memory, swap included. On a machine whose Docker VM other work shares,
# an uncapped suite took memory those runs needed and they were killed.
memory="${CORDON_PREPUSH_MEMORY:-10g}"
# And on its workers: `-n auto` starts one per core, and each holds its own memory.
workers="${CORDON_PREPUSH_WORKERS:-8}"

# Rebuilt only when the toolchain changes: tagged with its lock file's blob hash.
tag="cordon-prepush:$(git -C "$root" hash-object ci/dev-requirements.txt | cut -c1-12)"
if ! docker image inspect "$tag" >/dev/null 2>&1; then
    echo "prepush: building $tag (once per dependency change)"
    docker build -q -t "$tag" -f "$root/scripts/checks/prepush/Dockerfile" "$root" >/dev/null
    # The image for the previous dependency set is now unused.
    docker images --format '{{.Repository}}:{{.Tag}}' | grep '^cordon-prepush:' | grep -v "^$tag$" \
        | xargs -r docker rmi >/dev/null 2>&1 || true
fi

echo "prepush: checking $(git -C "$root" rev-parse --short HEAD) in $tag (memory $memory, $workers workers)"
docker run --rm --init --memory "$memory" --memory-swap "$memory" \
    -v "$root:/src:ro" \
    -e mode="$mode" \
    -e CORDON_PREPUSH_WORKERS="$workers" \
    "$tag" sh -c '
        set -e
        git clone -q /src /work
        cd /work
        python -m pip install -q --no-deps --disable-pip-version-check -e .
        set +e
        python scripts/checks/ci_parity.py $mode
        status=$?
        peak=$(cat /sys/fs/cgroup/memory.peak 2>/dev/null || echo unknown)
        kills=$(grep "^oom_kill " /sys/fs/cgroup/memory.events 2>/dev/null | cut -d" " -f2)
        echo "prepush: memory peak $peak bytes, processes killed by the cap: ${kills:-unknown}"
        if [ "${kills:-0}" -gt 0 ]; then
            echo "prepush: FAILED, killed by the memory cap; raise CORDON_PREPUSH_MEMORY or lower CORDON_PREPUSH_WORKERS"
            exit 1
        fi
        exit $status
    '
