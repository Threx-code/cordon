#!/bin/sh
# Regenerates the real-world vcpkg conformance case: a manifest-mode project (a builtin-baseline,
# `version>=` constraints, an override, features with a platform expression, a host dependency, an
# optional feature, an overlay port) whose install plan vcpkg computes with `install --dry-run` --
# nothing is downloaded or built. That plan is the authoritative inventory. The overlay port's
# portfile is never run. Run inside Docker only:
#
#   docker run --rm -v "$PWD/tests/conformance:/conformance" debian:12-slim sh /conformance/generate/vcpkg.sh
set -eu
OUT=/conformance/cases/vcpkg/real-manifest
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq git curl zip unzip tar ca-certificates pkg-config python3 g++ make ninja-build cmake >/dev/null 2>&1
git clone --quiet https://github.com/microsoft/vcpkg /tmp/vcpkg
BASELINE=$(git -C /tmp/vcpkg rev-parse HEAD)
/tmp/vcpkg/bootstrap-vcpkg.sh -disableMetrics >/tmp/bootstrap.log 2>&1 || { tail -20 /tmp/bootstrap.log; exit 1; }

rm -rf /tmp/p && mkdir -p /tmp/p/ports/acme-utils && cd /tmp/p
cat > vcpkg.json <<EOF
{
  "\$schema": "https://raw.githubusercontent.com/microsoft/vcpkg-tool/main/docs/vcpkg.schema.json",
  "name": "conformance",
  "version": "0.1.0",
  "dependencies": [
    "fmt",
    { "name": "spdlog", "version>=": "1.13.0" },
    { "name": "curl", "default-features": false, "features": ["ssl"], "platform": "linux | osx" },
    { "name": "vcpkg-cmake", "host": true },
    "acme-utils"
  ],
  "features": {
    "tests": {
      "description": "Build the tests",
      "dependencies": ["gtest"]
    }
  },
  "overrides": [
    { "name": "fmt", "version": "10.2.1" }
  ],
  "builtin-baseline": "$BASELINE"
}
EOF
# The builtin registry's baseline is vcpkg.json's builtin-baseline; the configuration adds the
# overlay ports.
cat > vcpkg-configuration.json <<'EOF'
{
  "overlay-ports": ["./ports"]
}
EOF
cat > ports/acme-utils/vcpkg.json <<'EOF'
{
  "name": "acme-utils",
  "version": "1.4.0",
  "dependencies": ["zlib"]
}
EOF
printf 'message(FATAL_ERROR "the conformance overlay port is never built")\n' > ports/acme-utils/portfile.cmake

/tmp/vcpkg/vcpkg install --dry-run  --x-manifest-root=. --x-install-root=/tmp/installed >/tmp/plan.txt 2>&1 || { tail -30 /tmp/plan.txt; exit 1; }

rm -rf "$OUT" && mkdir -p "$OUT/ports/acme-utils"
cp vcpkg.json vcpkg-configuration.json "$OUT/"
cp ports/acme-utils/vcpkg.json ports/acme-utils/portfile.cmake "$OUT/ports/acme-utils/"

python3 - "$OUT" <<'PY'
import json, re, sys
plan = open("/tmp/plan.txt").read()
found = set()
for name, triplet, version in re.findall(r"^\s+\*?\s*([a-z0-9-]+)(?:\[[^\]]*\])?:([a-z0-9-]+)@([^\s#]+)", plan, re.M):
    found.add(f"{name}@{version}")
overridden = {"fmt"}
ignore = {
    n.split("@")[0]: "resolved from the registry's version database at the builtin-baseline, which the repository does not hold"
    for n in found if n.split("@")[0] not in overridden
}
ignore["acme-utils"] = "an overlay port: the project's own, read as source"
json.dump({"tool": "vcpkg install --dry-run (the install plan)", "packages": sorted(found), "ignore": ignore}, open(f"{sys.argv[1]}/authoritative.json", "w"), indent=1)
print(len(found), "packages")
PY
cat /tmp/plan.txt | head -40
echo done
