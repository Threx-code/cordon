#!/usr/bin/env bash
#
# cordon-image-scan.sh <image> [<label>] — scan a container image, layer by layer, nothing run.
#
# The image is saved to a tar and scanned against the organisation ceiling. Two outcomes are kept
# apart on purpose:
#
#   a finding that meets the policy (high, or malicious at any severity)   -> exit 1, blocks
#   an incomplete scan                                                     -> a warning, exit 0
#
# Why the split. An image scan is structurally incomplete under this policy: a statically linked
# binary (Traefik, Grafana, the exporters) is larger than the per-file limit, and matching the
# operating system's packages needs `--online`, which the policy forbids. With fail_on_incomplete
# the scanner reports exit 4 for every image, and exit 4 MASKS findings. So the verdict is taken
# from the findings themselves, and the reasons for incompleteness are printed, never hidden.
set -uo pipefail

image="${1:?usage: cordon-image-scan.sh <image> [<label>]}"
label="${2:-$(printf '%s' "$image" | tr -c 'A-Za-z0-9._-' '_')}"
root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
out="${CORDON_REPORT_DIR:-$root/cordon-reports}/images"
mkdir -p "$out"
command -v cordon-scanner >/dev/null || { echo "cordon-scanner is not installed" >&2; exit 2; }

# A directory, then the tar inside it: `mktemp` wants its X's last, and a template ending in
# `.tar` gave an EMPTY path on some systems - and `scan ""` scans the current directory, so the
# repository was scanned in the image's place and every image passed.
work="$(mktemp -d "${TMPDIR:-/tmp}/cordon-image.XXXXXX")" || exit 2
trap 'rm -rf "$work"' EXIT
tar="$work/image.tar"
docker save "$image" -o "$tar" || { echo "could not save $image" >&2; exit 2; }
[ -s "$tar" ] || { echo "saving $image produced no archive" >&2; exit 2; }

policy=()
[ -f "$root/cordon-policy.yaml" ] && policy=(--policy "$root/cordon-policy.yaml")
cordon-scanner scan "$tar" "${policy[@]}" --no-color \
  --format text --format "json:$out/$label.json" --format "sarif:$out/$label.sarif"

python3 - "$out/$label.json" "$image" <<'PY'
import json, sys
result = json.load(open(sys.argv[1]))
image = sys.argv[2]
order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
confidence = {"low": 0, "medium": 1, "high": 2, "confirmed": 3}
active = [f for f in result.get("findings", []) if not f.get("suppressed")]
blocking = [
    f for f in active
    if (order.get(f.get("severity"), 0) >= order["high"] or f.get("category") == "malicious")
    and confidence.get(f.get("confidence"), 0) >= confidence["medium"]
]
if not result.get("complete", True):
    reasons = [f["message"] for f in active if f.get("rule_id", "").startswith(("OPERATIONAL.IMAGE", "OPERATIONAL.SECRET_HISTORY"))]
    print(f"::warning title=Cordon image scan incomplete ({image})::" + " | ".join(r[:300] for r in reasons))
for f in blocking:
    loc = f.get("location", {})
    print(f"::error title={f['rule_id']} in {image}::{loc.get('path', '')}: {f.get('message', '')[:400]}")
print(f"{image}: {len(blocking)} finding(s) meet the policy; {len(active)} reported")
sys.exit(1 if blocking else 0)
PY
