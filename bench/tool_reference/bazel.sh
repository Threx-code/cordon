#!/bin/sh
# `bazel mod graph`: the module graph Bazel resolves from MODULE.bazel (Bazel's own resolution).
set -u
for repo in /data/bazel/*/; do
  mkdir -p "$repo.reference"
  [ -f "$repo/MODULE.bazel" ] || continue
  ( cd "$repo" && timeout 1200 bazelisk mod graph --output=json --include_builtin > .reference/graph.json 2> .reference/graph.err ) || true
done
