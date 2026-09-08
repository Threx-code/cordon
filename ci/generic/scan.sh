#!/usr/bin/env sh
#
# The whole contract, for any CI system with no template here.
#
# Read-only mount and no network: the scanner needs neither write access nor
# egress, so it is given neither. That is also the posture it recommends for
# everything else, and a tool that does not follow its own advice is hard to
# argue with.

set -eu

IMAGE="${CORDON_IMAGE:-ghcr.io/cordon-dev/cordon:0.1.0}"
TARGET="${1:-$PWD}"
FAIL_ON="${CORDON_FAIL_ON:-high}"

docker run --rm \
    --network none \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --user 65534:65534 \
    --memory 2g \
    --pids-limit 256 \
    -v "$TARGET:/scan:ro" \
    -v "$PWD/out:/out" \
    "$IMAGE" \
    scan /scan \
        --fail-on "$FAIL_ON" \
        --no-color \
        --format text \
        --format sarif:/out/cordon.sarif \
        --format json:/out/cordon-result.json

# 0 clean · 1 findings · 2 scanner error · 3 config error · 4 incomplete
