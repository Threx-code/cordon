#!/bin/sh
# Regenerates the real-world Bazel conformance case: a Bzlmod root module with bazel_deps from the
# Bazel Central Registry (one dev-only, one under a repo_name), a single_version_override, a
# git_override at a commit and an archive_override with its integrity, and a module extension, all
# resolved by Bazel into MODULE.bazel.lock. Bazel's own `bazel mod graph --output=json` is the
# authoritative inventory. Nothing is built. Run inside Docker only:
#
#   docker run --rm --entrypoint sh -v "$PWD/tests/conformance:/conformance" gcr.io/bazel-public/bazel:7.4.1 /conformance/generate/bazel.sh
set -eu
OUT=/conformance/cases/bazel/real-bzlmod
rm -rf /tmp/b && mkdir -p /tmp/b && cd /tmp/b
curl -sL -o /tmp/skylib.tar.gz https://github.com/bazelbuild/bazel-skylib/releases/download/1.7.1/bazel-skylib-1.7.1.tar.gz
if command -v openssl >/dev/null; then
  SKYLIB_SRI="sha256-$(openssl dgst -sha256 -binary /tmp/skylib.tar.gz | base64 -w0)"
else
  SKYLIB_SRI="sha256-$(python3 -c 'import base64, hashlib, sys; print(base64.b64encode(hashlib.sha256(open(sys.argv[1], "rb").read()).digest()).decode())' /tmp/skylib.tar.gz)"
fi
ZLIB_SHA=$(curl -sL https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz | sha256sum | cut -d" " -f1)
RULES_PKG=$(git ls-remote https://github.com/bazelbuild/rules_pkg refs/tags/1.0.1 | cut -f1)
cat > MODULE.bazel <<EOF
module(
    name = "conformance",
    version = "0.1.0",
)

bazel_dep(name = "platforms", version = "0.0.10")
bazel_dep(name = "bazel_skylib", version = "1.7.1")
bazel_dep(name = "abseil-cpp", version = "20240722.0", repo_name = "com_google_absl")
bazel_dep(name = "rules_license", version = "1.0.0", dev_dependency = True)
bazel_dep(name = "rules_pkg", version = "1.0.1")

# Everything in the graph gets this platforms, whatever its own bazel_deps ask for.
single_version_override(
    module_name = "platforms",
    version = "0.0.11",
)

# From the repository at a commit, not from the registry.
git_override(
    module_name = "rules_pkg",
    remote = "https://github.com/bazelbuild/rules_pkg.git",
    commit = "$RULES_PKG",
)

# The release archive itself, checked against its integrity.
archive_override(
    module_name = "bazel_skylib",
    urls = ["https://github.com/bazelbuild/bazel-skylib/releases/download/1.7.1/bazel-skylib-1.7.1.tar.gz"],
    integrity = "$SKYLIB_SRI",
)

cc_configure = use_extension("@bazel_tools//tools/cpp:cc_configure.bzl", "cc_configure_extension")
use_repo(cc_configure, "local_config_cc")

# A repository rule declared in MODULE.bazel (Bazel 7.1+), with its archive's checksum.
http_archive = use_repo_rule("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "zlib_src",
    urls = ["https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz"],
    sha256 = "$ZLIB_SHA",
    strip_prefix = "zlib-1.3.1",
    build_file_content = "filegroup(name = 'all', srcs = glob(['**']))",
)
EOF
cat > BUILD.bazel <<'EOF'
load("@bazel_skylib//rules:write_file.bzl", "write_file")

write_file(
    name = "hello",
    out = "hello.txt",
    content = ["hello"],
)

cc_library(
    name = "lib",
    deps = ["@com_google_absl//absl/strings"],
)
EOF
touch WORKSPACE.bzlmod
bazel mod deps --lockfile_mode=update >/tmp/deps.log 2>&1 || { tail -30 /tmp/deps.log; exit 1; }
# bazel_tools' own dependencies (rules_java, protobuf, zlib, ...) are in the build too: every
# module depends on bazel_tools, so the graph shows it unexpanded, and its subgraph is asked for
# from it.
bazel mod graph --output=json --include_builtin >/tmp/graph.json 2>>/tmp/deps.log
bazel mod graph --output=json --include_builtin --from=bazel_tools >/tmp/tools.json 2>>/tmp/deps.log
rm -rf "$OUT" && mkdir -p "$OUT"
cp MODULE.bazel BUILD.bazel MODULE.bazel.lock "$OUT/"
{ printf '{"root": '; cat /tmp/graph.json; printf ', "bazel_tools": '; cat /tmp/tools.json; printf '}\n'; } > "$OUT/authoritative.raw.json"
head -c 2000 MODULE.bazel.lock; echo
echo done
