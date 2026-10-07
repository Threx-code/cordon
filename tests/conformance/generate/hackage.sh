#!/bin/sh
# Regenerates the real-world Hackage conformance cases. Nothing is compiled: cabal and stack only
# solve and lock.
#
#   real-cabal  a package (library, executable, test suite; a flag; conditionals) in a
#               cabal.project with a git source-repository-package and constraints. `cabal freeze`
#               writes the freeze file; Cabal's own install plan (`--dry-run`'s plan.json) is the
#               authoritative inventory.
#   real-stack  a Stack project on an LTS snapshot with extra-deps (a Hackage package pinned to a
#               revision, a git dependency) and flags. `stack ls dependencies` is authoritative.
#
# Run inside Docker only:
#
#   docker run --rm -v "$PWD/tests/conformance:/conformance" haskell:9.6 sh /conformance/generate/hackage.sh
#   docker run --rm -v "$PWD/tests/conformance:/conformance" python:3.12-slim python /conformance/generate/hackage_inventory.py
#
# The haskell image's Debian mirror no longer serves python3, so the first step leaves the tools'
# raw output in cases/hackage/.raw and the second turns it into authoritative.json and removes it.
set -eu
CASES=/conformance/cases/hackage
RAW="$CASES/.raw"
mkdir -p "$RAW"

# --- Cabal -----------------------------------------------------------------------------------
rm -rf /tmp/c && mkdir -p /tmp/c/src /tmp/c/app /tmp/c/test && cd /tmp/c
cat > conformance.cabal <<'EOF'
cabal-version:      3.0
name:               conformance
version:            0.1.0.0
license:            MIT
build-type:         Simple

flag dev
  description: Development extras
  default:     False
  manual:      True

common shared
  build-depends:
      base >=4.17 && <5
    , text ^>=2.0

library
  import:           shared
  exposed-modules:  Conformance
  hs-source-dirs:   src
  build-depends:
      aeson >=2.1 && <2.3
    , containers
    , safe
  if os(windows)
    build-depends: Win32
  else
    build-depends: unix
  if flag(dev)
    build-depends: pretty-simple
  default-language: Haskell2010

executable conformance
  import:           shared
  main-is:          Main.hs
  hs-source-dirs:   app
  build-depends:    conformance, optparse-applicative ^>=0.18
  default-language: Haskell2010

test-suite spec
  import:           shared
  type:             exitcode-stdio-1.0
  main-is:          Spec.hs
  hs-source-dirs:   test
  build-depends:    conformance, hspec >=2.10
  default-language: Haskell2010
EOF
(cd / && cabal update >/dev/null 2>&1)
SAFE=$(GIT_TERMINAL_PROMPT=0 git ls-remote https://github.com/ndmitchell/safe refs/tags/v0.3.21 | cut -f1)
cat > cabal.project <<EOF
packages: .

source-repository-package
  type: git
  location: https://github.com/ndmitchell/safe
  tag: $SAFE

constraints:
  aeson ^>=2.2,
  text -simdutf

tests: True
EOF
cabal freeze >/tmp/freeze.log 2>&1 || { tail -20 /tmp/freeze.log; exit 1; }
cabal build all --dry-run >/tmp/plan.log 2>&1 || { tail -20 /tmp/plan.log; exit 1; }

OUT="$CASES/real-cabal"
rm -rf "$OUT" && mkdir -p "$OUT"
cp conformance.cabal cabal.project cabal.project.freeze "$OUT/"
cp dist-newstyle/cache/plan.json "$RAW/plan.json"

# --- Stack -----------------------------------------------------------------------------------
rm -rf /tmp/s && mkdir -p /tmp/s/src && cd /tmp/s
cat > package.yaml <<'EOF'
name: stackapp
version: 0.1.0
dependencies:
  - base >= 4.17 && < 5
  - text
  - aeson
  - acme-missiles
  - optics-core
library:
  source-dirs: src
EOF
cat > stack.yaml <<'EOF'
resolver: lts-22.33
packages:
  - .
extra-deps:
  - acme-missiles-0.3@rev:0
  - git: https://github.com/well-typed/optics
    commit: 3a7a3a9c1a1c8d8b8f8e8d8c8b8a898887868584
    subdirs:
      - optics-core
flags:
  aeson:
    ordered-keymap: false
EOF
OPTICS=$(GIT_TERMINAL_PROMPT=0 git ls-remote https://github.com/well-typed/optics refs/tags/v0.4.1 | cut -f1)
sed -i "s/3a7a3a9c1a1c8d8b8f8e8d8c8b8a898887868584/$OPTICS/" stack.yaml
stack --allow-different-user --system-ghc --no-install-ghc ls dependencies json >/tmp/stack-deps.json 2>/tmp/stack.log || {
  stack --allow-different-user --install-ghc ls dependencies json >/tmp/stack-deps.json 2>>/tmp/stack.log || { tail -20 /tmp/stack.log; exit 1; }
}
OUT="$CASES/real-stack"
rm -rf "$OUT" && mkdir -p "$OUT"
cp package.yaml stack.yaml stack.yaml.lock "$OUT/"
cp /tmp/stack-deps.json "$RAW/stack-deps.json"
cat stack.yaml.lock
head -20 /tmp/c/cabal.project.freeze
echo done
