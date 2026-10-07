#!/bin/sh
# Regenerates the real-world Julia conformance case: Pkg resolves a package project (registry
# packages with compat bounds, a git dependency at a tag, a path dependency developed in the
# repository, a weak dependency with an extension, the julia compat) and writes Manifest.toml.
# Pkg's own `Pkg.dependencies()` -- independent of the manifest parser -- is the authoritative
# inventory. Packages are downloaded, never loaded or built (JULIA_PKG_PRECOMPILE_AUTO=0). Run
# inside Docker only:
#
#   docker run --rm -v "$PWD/tests/conformance:/conformance" julia:1.11 sh /conformance/generate/julia.sh
set -eu
OUT=/conformance/cases/julia/real-project
export JULIA_PKG_PRECOMPILE_AUTO=0 JULIA_DEPOT_PATH=/tmp/depot
rm -rf /tmp/j && mkdir -p /tmp/j/src /tmp/j/ext /tmp/j/LocalUtils/src && cd /tmp/j

cat > LocalUtils/Project.toml <<'EOF'
name = "LocalUtils"
uuid = "5c1f8d2a-3b7e-4f0a-9c61-2d84e0b7a913"
version = "0.1.0"

[deps]
Printf = "de0858da-6303-5e67-8744-51eddeeeb8d7"
EOF
printf 'module LocalUtils\nend\n' > LocalUtils/src/LocalUtils.jl
cat > Project.toml <<'EOF'
name = "Conformance"
uuid = "8f0b6e7c-2a41-4d3b-b5e9-7c1d0a6f4e22"
version = "0.1.0"
EOF
printf 'module Conformance\nend\n' > src/Conformance.jl
printf 'module ConformanceJSONExt\nend\n' > ext/ConformanceJSONExt.jl

julia --startup-file=no -e '
using Pkg
Pkg.activate(".")
Pkg.add(["JSON3", "OrderedCollections"])
Pkg.add(url="https://github.com/JuliaLang/Example.jl", rev="v0.5.5")
Pkg.develop(path="LocalUtils")
Pkg.compat("julia", "1.10")
Pkg.compat("JSON3", "1.13")
Pkg.compat("OrderedCollections", "1.6, 2")
' >/tmp/julia.log 2>&1 || { tail -30 /tmp/julia.log; exit 1; }

# A weak dependency and the extension it enables (Julia 1.9+): written into Project.toml the way
# a package author does, then resolved again so the manifest records it.
cat >> Project.toml <<'EOF'

[weakdeps]
JSON = "682c06a0-de6a-54ab-a142-c8b1cf79cde6"

[extensions]
ConformanceJSONExt = "JSON"
EOF
julia --startup-file=no -e 'using Pkg; Pkg.activate("."); Pkg.resolve()' >>/tmp/julia.log 2>&1 || { tail -30 /tmp/julia.log; exit 1; }

# A platform-specific artifact the package downloads at install: the binaries per os/arch.
cat > Artifacts.toml <<'EOF'
[[conformance_data]]
arch = "x86_64"
git-tree-sha1 = "4f0d4b9e9b9a3b8b1d0f5e3a2c1b0a9f8e7d6c5b"
os = "linux"
libc = "glibc"

    [[conformance_data.download]]
    sha256 = "0e6b9a1c4d7f2e5a8b3c6d9f0a1e4b7c2d5f8a3b6c9e0d1f4a7b2c5e8d1f4a7b"
    url = "https://github.com/acme/conformance-data/releases/download/v1.0.0/data.x86_64-linux-gnu.tar.gz"

[[conformance_data]]
arch = "aarch64"
git-tree-sha1 = "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b"
os = "macos"

    [[conformance_data.download]]
    sha256 = "7c2d5f8a3b6c9e0d1f4a7b2c5e8d1f4a7b0e6b9a1c4d7f2e5a8b3c6d9f0a1e4b"
    url = "https://github.com/acme/conformance-data/releases/download/v1.0.0/data.aarch64-apple-darwin.tar.gz"
EOF

rm -rf "$OUT" && mkdir -p "$OUT"
cp -r Project.toml Manifest.toml Artifacts.toml src ext LocalUtils "$OUT/"

julia --startup-file=no -e '
using Pkg
Pkg.activate(".")
deps = Pkg.dependencies()
pkgs = String[]
for (uuid, info) in deps
    info.version === nothing && continue
    info.is_tracking_path && continue
    push!(pkgs, "$(info.name)@$(info.version)")
end
sort!(pkgs)
# Standard libraries carry their Julia version in 1.11 manifests and are listed like any package.
# Artifacts are binaries, not packages: Pkg.dependencies() does not list them.
open(joinpath(ARGS[1], "authoritative.json"), "w") do io
    print(io, "{\n \"tool\": \"Pkg.dependencies()\",\n \"packages\": [", join(["\"$p\"" for p in pkgs], ", "), "],\n")
    print(io, " \"ignore\": {\"artifact:conformance_data\": \"an artifact (a platform binary from Artifacts.toml), not a package: Pkg.dependencies() lists packages\"}\n}\n")
end
println("packages ", length(pkgs))
' "$OUT"
head -50 Manifest.toml
echo done
