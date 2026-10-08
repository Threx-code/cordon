#!/bin/sh
# What CI will say about the commit being pushed, said before it is pushed.
#
#   scripts/prepush.sh           everything CI runs, the full suite included (about 15 minutes)
#   scripts/prepush.sh --quick   everything but the suite, perf and fuzz (about 5 minutes)
#
# Installed as the pre-push hook by `make hooks`. Nothing runs on the host but git and the
# Docker CLI: the checks run in a container, against a clean clone of HEAD, so the working
# tree's uncommitted and gitignored files neither help nor hurt. See scripts/ci_parity.py for
# what runs, and scripts/portability.py for the checks aimed at Windows and macOS.
#
# A push that must go out with this failing is `git push --no-verify`, and the failure is then
# CI's to report.
set -eu

root=$(git rev-parse --show-toplevel)
mode=""
[ "${1:-}" = "--quick" ] && mode="--quick"

command -v docker >/dev/null 2>&1 || { echo "prepush: Docker is required" >&2; exit 2; }

# Rebuilt only when the dependencies change: tagged with pyproject.toml's blob hash.
tag="cordon-prepush:$(git -C "$root" hash-object pyproject.toml | cut -c1-12)"
if ! docker image inspect "$tag" >/dev/null 2>&1; then
    echo "prepush: building $tag (once per dependency change)"
    docker build -q -t "$tag" -f "$root/scripts/prepush/Dockerfile" "$root" >/dev/null
    # The image for the previous dependency set is now unused.
    docker images --format '{{.Repository}}:{{.Tag}}' | grep '^cordon-prepush:' | grep -v "^$tag$" \
        | xargs -r docker rmi >/dev/null 2>&1 || true
fi

echo "prepush: checking $(git -C "$root" rev-parse --short HEAD) in $tag"
docker run --rm --init \
    -v "$root:/src:ro" \
    -e mode="$mode" \
    "$tag" sh -c '
        set -e
        git clone -q /src /work
        cd /work
        python -m pip install -q --no-deps --disable-pip-version-check -e .
        python scripts/ci_parity.py $mode
    '
