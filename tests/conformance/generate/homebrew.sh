#!/bin/sh
# Regenerates the real-world Homebrew conformance case: the current formula and cask sources from
# homebrew-core and homebrew-cask, a Brewfile using every bundle category, and Homebrew's own
# reading of each (formulae.brew.sh's JSON API, fetched at the same moment, so source and
# reference are the same revision) as the reference the expectations are written from: their
# dependencies, source URLs and checksums. Nothing is installed or evaluated. Run inside Docker
# only:
#
#   docker run --rm -v "$PWD/tests/conformance:/conformance" curlimages/curl:latest sh /conformance/generate/homebrew.sh
set -eu
OUT=/conformance/cases/homebrew/real-taps
REF=/conformance/generate/.homebrew-reference
rm -rf "$OUT" "$REF" && mkdir -p "$OUT/Formula" "$OUT/Casks" "$REF"
for formula in jq wget; do
  curl -fsSL "https://raw.githubusercontent.com/Homebrew/homebrew-core/HEAD/Formula/$(printf %.1s "$formula")/$formula.rb" > "$OUT/Formula/$formula.rb"
  curl -fsSL "https://formulae.brew.sh/api/formula/$formula.json" > "$REF/$formula.json"
done
curl -fsSL https://raw.githubusercontent.com/Homebrew/homebrew-cask/HEAD/Casks/f/firefox.rb > "$OUT/Casks/firefox.rb"
curl -fsSL https://formulae.brew.sh/api/cask/firefox.json > "$REF/firefox.json"
cat > "$OUT/Brewfile" <<'EOF'
tap "hashicorp/tap"
tap "acme/tools", "https://git.acme.example.internal/homebrew/tools.git"
brew "jq"
brew "wget", args: ["with-libpsl"]
brew "hashicorp/tap/terraform"
brew "postgresql@16", restart_service: :changed, link: true
cask "firefox"
cask "visual-studio-code", greedy: true
mas "Xcode", id: 497799835
vscode "ms-python.python"
whalebrew "whalebrew/wget"
EOF
head -40 "$OUT/Formula/wget.rb"
echo done
