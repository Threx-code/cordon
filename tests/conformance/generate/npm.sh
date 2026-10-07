#!/bin/sh
# Regenerates the real-world npm-family conformance cases: the package managers themselves resolve
# one project and write their lockfiles, and npm's own `ls` is kept as the authoritative inventory
# the scan is compared with. Run inside Docker only (see tests/conformance/README.md):
#
#   docker run --rm -v "$PWD/tests/conformance:/conformance" node:22-slim sh /conformance/generate/npm.sh
#
# Scripts are never run (`--ignore-scripts`): only resolution happens.
set -eu
OUT=/conformance/cases/npm
apt-get update -qq >/dev/null && apt-get install -y -qq git ca-certificates >/dev/null
corepack enable >/dev/null 2>&1 || true

project() {
  dir=$1
  rm -rf "$dir" && mkdir -p "$dir/packages/util"
  cat > "$dir/package.json" <<'EOF'
{
  "name": "conformance-app",
  "version": "1.0.0",
  "private": true,
  "workspaces": ["packages/*"],
  "dependencies": {
    "lodash": "^4.17.20",
    "@types/node": "20.11.30",
    "chalk-four": "npm:chalk@4.1.2",
    "react-dom": "18.2.0",
    "react": "18.2.0",
    "is-number": "github:jonschlinkert/is-number#98e8ff1da1a89f93d1397a24d7413ed15421c139",
    "local-util": "file:packages/util"
  },
  "devDependencies": {
    "left-pad": "1.3.0"
  },
  "optionalDependencies": {
    "fsevents": "2.3.3"
  },
  "overrides": {
    "loose-envify": "1.4.0"
  }
}
EOF
  cat > "$dir/packages/util/package.json" <<'EOF'
{"name": "local-util", "version": "0.1.0", "dependencies": {"ms": "2.1.3"}}
EOF
}

# npm: lockfile v3, and npm's own view of the tree.
project /tmp/npm
cd /tmp/npm
npm install --package-lock-only --ignore-scripts --no-audit --no-fund >/dev/null
npm ls --all --json --package-lock-only > /tmp/npm-ls.json || true
mkdir -p "$OUT/real-npm-v3"
cp package.json package-lock.json "$OUT/real-npm-v3/"
mkdir -p "$OUT/real-npm-v3/packages/util" && cp packages/util/package.json "$OUT/real-npm-v3/packages/util/"
node -e '
// npm keys an aliased package by its alias and lists workspace members beside fetched packages.
// The real package name is the one in the registry URL npm resolved; a member resolves to a
// path (file:) and is the project, not a dependency.
const ls = require("/tmp/npm-ls.json"); const out = new Set();
const real = (alias, d) => { const m = /registry\.npmjs\.org\/((?:@[^/]+\/)?[^/]+)\/-\//.exec(d.resolved || ""); return m ? m[1] : alias; };
(function walk(deps) { for (const [n, d] of Object.entries(deps || {})) { if (d.version && !String(d.resolved || "").startsWith("file:")) out.add(real(n, d) + "@" + d.version); walk(d.dependencies); } })(ls.dependencies);
require("fs").writeFileSync(process.argv[1], JSON.stringify({tool: "npm ls --all --json", packages: [...out].sort()}, null, 1));
' "$OUT/real-npm-v3/authoritative.json"

# pnpm (v9 lockfile).
project /tmp/pnpm
cd /tmp/pnpm
printf 'packages:\n  - "packages/*"\n' > pnpm-workspace.yaml
npx -y pnpm@9.12.0 install --lockfile-only --ignore-scripts >/dev/null
mkdir -p "$OUT/real-pnpm-v9/packages/util"
cp package.json pnpm-lock.yaml pnpm-workspace.yaml "$OUT/real-pnpm-v9/"
cp packages/util/package.json "$OUT/real-pnpm-v9/packages/util/"
# The identical project, resolved the same day: npm's lockfile-only inventory is the independent
# inventory pnpm's and Yarn Classic's lockfiles are compared with.
node -e '
const truth = require(process.argv[1]); truth.tool = "npm ls --all --package-lock-only, the identical project resolved the same day";
require("fs").writeFileSync(process.argv[2], JSON.stringify(truth, null, 1));
' "$OUT/real-npm-v3/authoritative.json" "$OUT/real-pnpm-v9/authoritative.json"

# Yarn Classic (v1).
project /tmp/yarn1
cd /tmp/yarn1
npx -y yarn@1.22.22 install --ignore-scripts --ignore-engines --no-progress --non-interactive >/dev/null
mkdir -p "$OUT/real-yarn-classic/packages/util"
cp package.json yarn.lock "$OUT/real-yarn-classic/"
cp packages/util/package.json "$OUT/real-yarn-classic/packages/util/"
node -e '
const truth = require(process.argv[1]); truth.tool = "npm ls --all --package-lock-only, the identical project resolved the same day";
require("fs").writeFileSync(process.argv[2], JSON.stringify(truth, null, 1));
' "$OUT/real-npm-v3/authoritative.json" "$OUT/real-yarn-classic/authoritative.json"

# Yarn 4 (berry).
project /tmp/yarn4
cd /tmp/yarn4
printf 'nodeLinker: node-modules\nenableScripts: false\n' > .yarnrc.yml
corepack use yarn@4.5.1 >/dev/null 2>&1 || true
YARN_ENABLE_IMMUTABLE_INSTALLS=false corepack yarn@4.5.1 install --mode=update-lockfile >/dev/null
mkdir -p "$OUT/real-yarn-berry/packages/util"
cp package.json yarn.lock "$OUT/real-yarn-berry/"
cp packages/util/package.json "$OUT/real-yarn-berry/packages/util/"
# Yarn's own reading of the project's resolutions (every locator, recursively).
corepack yarn@4.5.1 info --all --recursive --json > /tmp/yarn-info.jsonl 2>/dev/null || true
node -e '
const lines = require("fs").readFileSync("/tmp/yarn-info.jsonl", "utf8").split("\n").filter(Boolean);
const out = new Set();
for (const line of lines) { const v = JSON.parse(line).value || ""; const m = /^((?:@[^/@]+\/)?[^/@]+)@(npm|https?|git|github):.*?$/.exec(v);
  const version = (JSON.parse(line).children || {}).Version; if (m && version && !/workspace:|file:|link:|patch:/.test(v)) out.add(m[1] + "@" + version); }
require("fs").writeFileSync(process.argv[1], JSON.stringify({tool: "yarn info --all --recursive --json", packages: [...out].sort()}, null, 1));
' "$OUT/real-yarn-berry/authoritative.json"

# npm-shrinkwrap.json: the same resolution under the name a published package ships it as.
cd /tmp/npm
cp package-lock.json npm-shrinkwrap.json
mkdir -p "$OUT/real-npm-shrinkwrap/packages/util"
cp package.json npm-shrinkwrap.json "$OUT/real-npm-shrinkwrap/"
cp packages/util/package.json "$OUT/real-npm-shrinkwrap/packages/util/"
cp "$OUT/real-npm-v3/authoritative.json" "$OUT/real-npm-shrinkwrap/authoritative.json"

# A package with bundled dependencies, a nested (non-hoisted) install, and overrides.
rm -rf /tmp/nest && mkdir -p /tmp/nest && cd /tmp/nest
cat > package.json <<'EOF'
{
  "name": "nesting-app",
  "version": "1.0.0",
  "dependencies": {"debug": "2.6.9", "ms": "2.1.3", "npm-bundled": "1.1.2"},
  "overrides": {"ms@2.0.0": "2.0.0"},
  "scripts": {"postinstall": "node scripts/setup.js", "test": "node test.js"}
}
EOF
npm install --package-lock-only --ignore-scripts --no-audit --no-fund >/dev/null
npm ls --all --json --package-lock-only > /tmp/nest-ls.json || true
mkdir -p "$OUT/real-npm-nested"
cp package.json package-lock.json "$OUT/real-npm-nested/"
node -e '
const ls = require("/tmp/nest-ls.json"); const out = new Set();
(function walk(deps) { for (const [n, d] of Object.entries(deps || {})) { if (d.version) out.add(n + "@" + d.version); walk(d.dependencies); } })(ls.dependencies);
require("fs").writeFileSync(process.argv[1], JSON.stringify({tool: "npm ls --all --json --package-lock-only", packages: [...out].sort()}, null, 1));
' "$OUT/real-npm-nested/authoritative.json"

echo done
