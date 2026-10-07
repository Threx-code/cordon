#!/bin/sh
# Bun's text lockfile and Deno's lockfile, written by Bun and Deno. Run inside Docker only:
#
#   docker run --rm -v "$PWD/tests/conformance:/conformance" oven/bun:1.2 sh /conformance/generate/bun-deno.sh bun
#   docker run --rm -v "$PWD/tests/conformance:/conformance" denoland/deno:2.1.4 sh /conformance/generate/bun-deno.sh deno
set -eu
TOOL=$1
rm -rf /tmp/p && mkdir -p /tmp/p && cd /tmp/p
if [ "$TOOL" = bun ]; then
  OUT=/conformance/cases/npm/real-bun
  mkdir -p packages/util
  cat > package.json <<'EOF'
{
  "name": "bun-app",
  "version": "1.0.0",
  "workspaces": ["packages/*"],
  "dependencies": {"chalk": "4.1.2", "@types/node": "20.11.30", "local-util": "workspace:*"},
  "devDependencies": {"left-pad": "1.3.0"},
  "optionalDependencies": {"fsevents": "2.3.3"}
}
EOF
  echo '{"name": "local-util", "version": "0.1.0", "dependencies": {"ms": "2.1.3"}}' > packages/util/package.json
  bun install --ignore-scripts --save-text-lockfile >/dev/null 2>&1 || bun install --ignore-scripts >/dev/null
  mkdir -p "$OUT/packages/util"
  cp package.json bun.lock "$OUT/"
  cp packages/util/package.json "$OUT/packages/util/"
  # Bun's own reading of the lockfile it wrote.
  bun pm ls --all > "$OUT/bun-pm-ls.txt" 2>/dev/null || true
else
  OUT=/conformance/cases/npm/real-deno
  cat > deno.json <<'EOF'
{
  "imports": {
    "chalk": "npm:chalk@4.1.2",
    "left-pad": "npm:left-pad@1.3.0",
    "@std/path": "jsr:@std/path@1.0.8"
  }
}
EOF
  printf 'import chalk from "chalk";\nimport leftPad from "left-pad";\nimport { join } from "@std/path";\nconsole.log(chalk, leftPad, join);\n' > main.ts
  deno install --entrypoint main.ts >/dev/null 2>&1 || deno cache main.ts >/dev/null
  mkdir -p "$OUT"
  cp deno.json deno.lock main.ts "$OUT/"
fi
echo "$TOOL done"
