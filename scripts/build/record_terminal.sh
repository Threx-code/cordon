#!/bin/bash
# Records the README terminal's sessions from the scanner itself (render them with
# scripts/build/render_terminal.py). Run from the repository root, in a container that has the
# scanner's development environment and util-linux `script`:
#
#   docker run --rm -v "$PWD:/repo" -w /repo <dev image> bash scripts/build/record_terminal.sh
#
# Each command runs in a pseudo-terminal at the grid's size, so the scanner draws what it draws for
# a person: its colours, its progress bars. The repository scanned is assembled from the project's
# own corpus (corpus/malicious and corpus/benign), so every finding shown is one a test asserts.
# The npm package and the image are fetched from their registries (--online), as a user's would be.
set -euo pipefail
REPO=$PWD
OUT=$REPO/docs/assets/terminal
mkdir -p "$OUT"
BIN=$(mktemp -d)
printf '#!/bin/sh\nexec python -m cordon_scanner "$@"\n' > "$BIN/cordon-scanner"
chmod +x "$BIN/cordon-scanner"
export PATH=$BIN:$PATH PYTHONPATH=$REPO/src COLORTERM=truecolor TERM=xterm-256color COLUMNS=112 LINES=26

C=$REPO/corpus
R=$(mktemp -d)/acme-platform
put() { mkdir -p "$R/$(dirname "$2")"; cp "$C/$1" "$R/$2"; }
put malicious/ci-secret-exfil/.github/workflows/release.yml .github/workflows/release.yml
put malicious/agent-skill-fetch-exec/.claude/skills/setup/SKILL.md .claude/skills/setup/SKILL.md
put malicious/agent-rules-hidden-text/CLAUDE.md CLAUDE.md
put malicious/mcp-server-poisoned-local/.mcp.json .mcp.json
put malicious/mcp-server-poisoned-local/node_modules/notes-mcp/index.js node_modules/notes-mcp/index.js
put malicious/mcp-server-poisoned-local/node_modules/notes-mcp/package.json node_modules/notes-mcp/package.json
put malicious/model-pickle-exec/model.pkl models/model.pkl
put malicious/secret-split-literal/deploy.js services/api/deploy.js
put malicious/secret-split-literal/settings.py services/api/settings.py
put malicious/exfil-python-install-hook/setup.py setup.py
put malicious/protestware-geo-wipe-node/lib/ssl-geo.js lib/ssl-geo.js
put malicious/trojan-source/access.js src/access.js
put malicious/credential-theft-js/telemetry.js src/telemetry.js
put malicious/typosquat-no-lockfile/package.json package.json
put malicious/iac-public-ingress/main.tf infra/main.tf
put malicious/k8s-rbac-wildcard/role.yaml deploy/k8s/role.yaml
put malicious/container-fetch-exec/Dockerfile Dockerfile
for d in python javascript ops config; do
  (cd "$C/benign/$d" && find . -type f ! -name expected.yaml) | while read -r f; do
    put "benign/$d/${f#./}" "services/$d/${f#./}"
  done
done
(cd "$R" && git init -q && git add -A && git -c user.name=demo -c user.email=demo@example.com commit -qm init)

record() {  # name, directory, command
  (cd "$2" && script -q -T "$OUT/$1.timing" -c "$3" "$OUT/$1.typescript" >/dev/null 2>&1) || true
  echo "$1: $(wc -l < "$OUT/$1.timing") writes"
}
record home "$R" "FORCE_COLOR=1 cordon-scanner | head -n 13"  # the banner and its environment; FORCE_COLOR keeps a pipe in colour
record repo "$R" "cordon-scanner scan ."
record npm "$R" "cordon-scanner scan pkg:npm/express --online"
record image "$R" "cordon-scanner scan pkg:docker/nginx@1.27 --online"
