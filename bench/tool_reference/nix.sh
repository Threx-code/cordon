#!/bin/sh
# `nix flake metadata`: the inputs Nix itself resolves from flake.nix and flake.lock.
set -u
for repo in /vol/tool-agreement/nix/*/; do
  mkdir -p "$repo.reference"; : > "$repo.reference/flakes.tsv"; n=0
  find "$repo" -name flake.lock -not -path '*/.reference/*' | while read -r lock; do
    n=$((n + 1)); dir=$(dirname "$lock")
    nix --extra-experimental-features 'nix-command flakes' flake metadata --json --no-write-lock-file --offline "path:$dir" > "$repo.reference/$n.json" 2>/dev/null \
      && printf '%s\t%s.json\n' "${dir#$repo}" "$n" >> "$repo.reference/flakes.tsv"
  done
done
