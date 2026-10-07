#!/bin/sh
# Fetches the YARA rules shipped as Cordon's built-in pack (`--yara builtin`): DataDog GuardDog's
# `threat-*` source-code rules, Apache-2.0, at the commit pinned here, with the licence. The
# rules are detection signatures, not samples. Which of them ship is decided by
# tests/conformance/generate/yara_select.py against the benign corpus. Run inside Docker only:
#
#   docker run --rm -v "$PWD/src/cordon_scanner/rules:/rules" curlimages/curl:latest sh /rules/../../../tests/conformance/generate/yara_pack.sh
set -eu
COMMIT=1f4a66c064fb2087c224750507f3b65c7633deeb
BASE="https://raw.githubusercontent.com/DataDog/guarddog/$COMMIT"
OUT=/rules/yara/upstream
rm -rf "$OUT" && mkdir -p "$OUT"
curl -fsSL "$BASE/LICENSE" -o "$OUT/LICENSE"
curl -fsSL "https://api.github.com/repos/DataDog/guarddog/contents/guarddog/analyzer/sourcecode?ref=$COMMIT" \
  | grep '"name": "threat-[a-z0-9-]*\.yar"' | sed 's/.*"name": "\([^"]*\)".*/\1/' > "$OUT/.names"
while read -r name; do
  curl -fsSL "$BASE/guarddog/analyzer/sourcecode/$name" -o "$OUT/$name"
done < "$OUT/.names"
rm "$OUT/.names"
echo "$COMMIT" > "$OUT/COMMIT"
ls "$OUT" | wc -l
