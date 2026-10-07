#!/bin/sh
# Regenerates the real-world installed-Homebrew conformance case: `brew bundle install` of a
# Brewfile (two well-known formulae, poured from Homebrew's own bottles), keeping each keg's
# INSTALL_RECEIPT.json -- what Homebrew records of an installed formula: on request or as a
# dependency, its tap, its runtime dependencies at their versions -- and nothing else of the
# install. `brew info --json=v2 --installed` is the reference. Run inside Docker only:
#
#   docker run --rm --platform linux/amd64 -v "$PWD/tests/conformance:/conformance" homebrew/brew:latest sh /conformance/generate/homebrew_installed.sh
set -eu
OUT=/conformance/cases/homebrew/real-installed
export HOMEBREW_NO_ANALYTICS=1 HOMEBREW_NO_INSTALL_CLEANUP=1 HOMEBREW_NO_ENV_HINTS=1
WORK=$(mktemp -d)
# The image's Homebrew may be older than the formulae the API serves.
brew update --quiet >/dev/null
printf 'brew "jq"\nbrew "wget"\n' > "$WORK/Brewfile"
brew bundle install --file="$WORK/Brewfile" >/dev/null
brew info --json=v2 --installed > "$WORK/installed.json"
rm -rf "$OUT" && mkdir -p "$OUT"
cp "$WORK/Brewfile" "$OUT/Brewfile"
[ -f "$WORK/Brewfile.lock.json" ] && cp "$WORK/Brewfile.lock.json" "$OUT/" || true
CELLAR=$(brew --cellar)
cd "$CELLAR"
for receipt in */*/INSTALL_RECEIPT.json; do
  mkdir -p "$OUT/linuxbrew/Cellar/$(dirname "$receipt")"
  cp "$receipt" "$OUT/linuxbrew/Cellar/$receipt"
done
cp "$WORK/installed.json" "$OUT/authoritative.raw.json"
find "$OUT" -type f | sort
echo done
