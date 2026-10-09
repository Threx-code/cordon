#!/bin/sh
# opam's own reading of each opam file (`opam show --just-file`): its `depends` formula, then,
# after a `@@ depopts` line, its optional dependencies. opam's warnings go to .reference/opam.err.
set -u
for repo in /data/opam/*/; do
  mkdir -p "$repo.reference"; : > "$repo.reference/opam.txt"; : > "$repo.reference/opam.err"
  find "$repo" \( -name '*.opam' -o -name opam -o -name '*.opam.locked' \) -type f -not -path '*/.reference/*' | while read -r file; do
    printf '### %s\n' "${file#$repo}" >> "$repo.reference/opam.txt"
    cp "$file" /tmp/read.opam
    (cd /tmp && opam show --just-file -f depends ./read.opam) >> "$repo.reference/opam.txt" 2>> "$repo.reference/opam.err"
    echo "@@ depopts" >> "$repo.reference/opam.txt"
    (cd /tmp && opam show --just-file -f depopts ./read.opam) >> "$repo.reference/opam.txt" 2>> "$repo.reference/opam.err"
    echo >> "$repo.reference/opam.txt"
  done
done
