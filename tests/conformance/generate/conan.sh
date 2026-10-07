#!/bin/sh
# Regenerates the real-world Conan conformance case: a conanfile.py (requires with a version range,
# an override, options, a tool_requires and a test_requires) and a conanfile.txt consumer beside
# it, resolved against ConanCenter by Conan 2 into conan.lock with a project profile. Only recipes
# are fetched -- nothing is built, and the project's conanfile.py is evaluated by Conan only to
# read its requirements. Conan's own `conan graph info` -- independent of the lockfile -- is the
# authoritative inventory. Run inside Docker only:
#
#   docker run --rm -v "$PWD/tests/conformance:/conformance" python:3.12-slim sh /conformance/generate/conan.sh
set -eu
OUT=/conformance/cases/conan/real-conan2
export CONAN_HOME=/tmp/conan-home
pip install --quiet --disable-pip-version-check "conan>=2.10,<3" >/dev/null 2>&1
rm -rf /tmp/c && mkdir -p /tmp/c/profiles /tmp/c/consumer && cd /tmp/c

cat > profiles/default <<'EOF'
[settings]
os=Linux
arch=x86_64
compiler=gcc
compiler.version=12
compiler.libcxx=libstdc++11
compiler.cppstd=17
build_type=Release

[options]
*:shared=False
EOF
cat > conanfile.py <<'EOF'
from conan import ConanFile


class App(ConanFile):
    name = "app"
    version = "0.1.0"
    settings = "os", "arch", "compiler", "build_type"
    default_options = {"fmt/*:header_only": True}

    def requirements(self):
        self.requires("fmt/[>=10 <11]")
        self.requires("libcurl/8.10.1")
        # Pin the zlib every package in the graph gets.
        self.requires("zlib/1.3.1", override=True)

    def build_requirements(self):
        self.tool_requires("cmake/[>=3.27 <4]")
        self.test_requires("gtest/1.15.0")
EOF
cat > consumer/conanfile.txt <<'EOF'
[requires]
spdlog/1.14.1
nlohmann_json/[~3.11]

[tool_requires]
ninja/1.12.1

[options]
spdlog/*:header_only=True

[generators]
CMakeDeps
CMakeToolchain

[layout]
cmake_layout
EOF

conan lock create . -pr:a profiles/default --lockfile-out=conan.lock >/tmp/conan.log 2>&1 || { tail -30 /tmp/conan.log; exit 1; }
conan lock create consumer -pr:a profiles/default --lockfile-out=consumer/conan.lock >>/tmp/conan.log 2>&1 || { tail -30 /tmp/conan.log; exit 1; }
conan graph info . -pr:a profiles/default --lockfile=conan.lock --format=json >/tmp/graph.json 2>>/tmp/conan.log
conan graph info consumer -pr:a profiles/default --lockfile=consumer/conan.lock --format=json >/tmp/graph-consumer.json 2>>/tmp/conan.log

rm -rf "$OUT" && mkdir -p "$OUT/profiles" "$OUT/consumer"
cp conanfile.py conan.lock "$OUT/"
cp profiles/default "$OUT/profiles/"
cp consumer/conanfile.txt consumer/conan.lock "$OUT/consumer/"

python3 - "$OUT" <<'PY'
import json, sys
found = set()
for path in ("/tmp/graph.json", "/tmp/graph-consumer.json"):
    graph = json.load(open(path))["graph"]["nodes"]
    for node in graph.values():
        ref = node.get("ref") or ""
        if not ref or ref.startswith(("conanfile", "app/")):
            continue
        name, _, rest = ref.partition("/")
        version = rest.split("#")[0].split("@")[0]
        found.add(f"{name}@{version}")
json.dump({"tool": "conan graph info --format=json", "packages": sorted(found), "lists_tools": True}, open(f"{sys.argv[1]}/authoritative.json", "w"), indent=1)
print(len(found), "packages")
PY
cat conan.lock consumer/conan.lock
echo done
