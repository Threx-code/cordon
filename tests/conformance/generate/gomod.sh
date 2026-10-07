#!/bin/sh
# Regenerates the real-world Go conformance cases: the go command resolves modules and writes
# go.mod, go.sum and vendor/modules.txt, and `go list -m all` (the go command's own build list) is
# kept as the authoritative inventory. Nothing is built. Run inside Docker only:
#
#   docker run --rm -v "$PWD/tests/conformance:/conformance" golang:1.24 sh /conformance/generate/gomod.sh
set -eu
OUT=/conformance/cases/gomod
export GOFLAGS=-mod=mod GOTOOLCHAIN=local

build_list() {
  # $1 directory, $2 output. The modules that supply packages to the build -- the main packages
  # and the declared tools -- as the go command resolves them (replacements applied). Not
  # `go list -m all`: that is the whole module graph, including modules whose code never builds.
  (cd "$1" && go list -deps -json ./... $(go list tool 2>/dev/null) | python3 -c '
import json, sys
text, decoder, index, out = sys.stdin.read(), json.JSONDecoder(), 0, []
while index < len(text):
    while index < len(text) and text[index].isspace():
        index += 1
    if index >= len(text):
        break
    package, index = decoder.raw_decode(text, index)
    if package.get("Module"):
        out.append(package["Module"])
for module in out:
    print(json.dumps(module))
') | python3 -c '
import json, sys
text = sys.stdin.read()
decoder, found, index = json.JSONDecoder(), set(), 0
while index < len(text):
    while index < len(text) and text[index].isspace():
        index += 1
    if index >= len(text):
        break
    module, index = decoder.raw_decode(text, index)
    if module.get("Main"):
        continue
    target = module.get("Replace") or module
    if target.get("Version"):
        found.add(target["Path"] + "@" + target["Version"])
json.dump({
    "tool": "go list -deps ./... and tools: the modules supplying packages (replacements applied)",
    "packages": sorted(found),
    "ignore": {"stdlib": "go list reports the standard library as packages with no module; its version is the toolchain directive go.mod records"},
    "lists_tools": True,
}, open(sys.argv[1], "w"), indent=1)
' "$2"
}

# One module: direct and indirect requirements, a pseudo-version, a replace to another module at
# a version, a local replace, an exclude, a tool directive, and the go/toolchain directives.
rm -rf /tmp/app && mkdir -p /tmp/app/localdep && cd /tmp/app
cat > go.mod <<'EOF'
module example.com/conformance/app

go 1.24

toolchain go1.24.0
EOF
cat > main.go <<'EOF'
package main

import (
	_ "github.com/google/uuid"
	_ "golang.org/x/text/language"
	_ "example.com/conformance/localdep"
)

func main() {}
EOF
cat > localdep/go.mod <<'EOF'
module example.com/conformance/localdep

go 1.24
EOF
echo 'package localdep' > localdep/localdep.go
go get github.com/google/uuid@v1.6.0 >/dev/null 2>&1
go get golang.org/x/text@v0.21.0 >/dev/null 2>&1
go mod edit -require=example.com/conformance/localdep@v0.0.0 -replace=example.com/conformance/localdep=./localdep
go mod edit -replace=github.com/pkg/errors=github.com/pkg/errors@v0.9.1
go mod edit -exclude=golang.org/x/text@v0.20.0
go get -tool golang.org/x/tools/cmd/stringer@v0.28.0 >/dev/null 2>&1
go mod tidy >/dev/null 2>&1
mkdir -p "$OUT/real-module/localdep"
cp go.mod go.sum main.go "$OUT/real-module/"
cp localdep/go.mod "$OUT/real-module/localdep/"
build_list /tmp/app "$OUT/real-module/authoritative.json"

# The same module vendored: vendor/modules.txt records what was copied in.
go mod vendor >/dev/null 2>&1
mkdir -p "$OUT/real-vendored/vendor" "$OUT/real-vendored/localdep"
cp go.mod go.sum main.go "$OUT/real-vendored/"
cp localdep/go.mod "$OUT/real-vendored/localdep/"
cp vendor/modules.txt "$OUT/real-vendored/vendor/"
cp "$OUT/real-module/authoritative.json" "$OUT/real-vendored/authoritative.json"

# A workspace: go.work joining two modules that share a requirement.
rm -rf /tmp/ws && mkdir -p /tmp/ws/svc-a /tmp/ws/svc-b && cd /tmp/ws
for m in svc-a svc-b; do
  (cd $m && go mod init "example.com/ws/$m" >/dev/null 2>&1 && printf 'package main\nimport _ "github.com/google/uuid"\nfunc main() {}\n' > main.go && go get github.com/google/uuid@v1.6.0 >/dev/null 2>&1 && go mod tidy >/dev/null 2>&1)
done
go work init ./svc-a ./svc-b
mkdir -p "$OUT/real-workspace/svc-a" "$OUT/real-workspace/svc-b"
cp go.work "$OUT/real-workspace/"
for m in svc-a svc-b; do cp $m/go.mod $m/go.sum $m/main.go "$OUT/real-workspace/$m/"; done
echo done
