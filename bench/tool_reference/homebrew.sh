#!/bin/sh
# `brew bundle list`: every entry Homebrew Bundle reads from a Brewfile. A Brewfile is Ruby and
# brew evaluates it, so this runs sandboxed (see sandbox.sh): no network, the files read-only,
# output to /out only.
set -u
export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 HOMEBREW_NO_ENV_HINTS=1
for repo in "${DATA:-/data}"/homebrew/*/; do
  name=$(basename "$repo"); mkdir -p "/out/homebrew/$name"; out="/out/homebrew/$name/brew.txt"; : > "$out"
  find "$repo" -type f \( -name 'Brewfile' -o -name 'Brewfile.*' -o -name '*.Brewfile' -o -name '.Brewfile' \) -not -path '*/.reference/*' | while read -r file; do
    printf '### %s\n' "${file#$repo}" >> "$out"
    for kind in formula cask tap mas vscode; do
      timeout 120 brew bundle list "--$kind" --file="$file" 2>> "/out/homebrew/$name/brew.err" | sed "s/^/$kind\t/" >> "$out"
    done
  done
done
