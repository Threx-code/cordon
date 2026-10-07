#!/bin/sh
# Lockfile versions 1 and 2, written by the npm releases that wrote them (npm 6 and npm 8), and
# read back by npm 8's `npm ls --package-lock-only`, which reads both from the lockfile alone.
# Run inside Docker only:
#
#   docker run --rm -v "$PWD/tests/conformance:/conformance" node:16 sh /conformance/generate/npm-legacy.sh
set -eu
for VERSION in 1 2; do
  OUT=/conformance/cases/npm/real-npm-v$VERSION
  rm -rf /tmp/p && mkdir -p /tmp/p && cd /tmp/p
  cat > package.json <<'EOF'
{
  "name": "legacy-app",
  "version": "1.0.0",
  "dependencies": {"chalk": "4.1.2", "@types/node": "20.11.30", "chalk-four": "npm:chalk@4.1.2"},
  "devDependencies": {"left-pad": "1.3.0"},
  "optionalDependencies": {"fsevents": "2.3.3"}
}
EOF
  if [ "$VERSION" = 1 ]; then
    npx -y npm@6.14.18 install --package-lock-only --ignore-scripts --no-audit >/dev/null 2>&1
  else
    npm install --package-lock-only --ignore-scripts --no-audit >/dev/null 2>&1
  fi
  grep -q "\"lockfileVersion\": $VERSION" package-lock.json
  mkdir -p "$OUT"
  cp package.json package-lock.json "$OUT/"
  npm ls --all --json --package-lock-only > /tmp/ls.json 2>/dev/null || true
  node -e '
const ls = require("/tmp/ls.json"); const out = new Set();
const real = (alias, d) => { const m = /registry\.npmjs\.org\/((?:@[^/]+\/)?[^/]+)\/-\//.exec(d.resolved || ""); return m ? m[1] : alias; };
(function walk(deps) { for (const [n, d] of Object.entries(deps || {})) { if (d.version) out.add(real(n, d) + "@" + d.version); walk(d.dependencies); } })(ls.dependencies);
require("fs").writeFileSync(process.argv[1], JSON.stringify({tool: "npm ls --all --json --package-lock-only (npm " + process.argv[2] + ")", packages: [...out].sort()}, null, 1));
' "$OUT/authoritative.json" "$(npm --version)"
  echo "v$VERSION: $(tr -d '\n ' < "$OUT/authoritative.json" | cut -c1-200)"
done
