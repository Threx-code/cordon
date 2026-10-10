#!/bin/sh
# The references that execute repository content -- a Brewfile is Ruby, a conanfile.py is Python --
# run here: no network (--network none), the collected files mounted read-only, output to a volume of its own, and
# copied into each repository's .reference/ afterwards by a container that runs nothing of theirs.
# Usage: bench/tool_reference/sandbox.sh homebrew|conan|hackage ...
set -u
here=$(cd "$(dirname "$0")" && pwd)
data=${CORDON_TOOL_VOLUME:-cordon-tool-agreement}
out=cordon-tool-sandbox-out
docker volume create "$out" >/dev/null
sealed() { docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
  -v "$data:/vol:ro" -v "$out:/out" -v "$here:/ref:ro" "$@"; }
for eco in "$@"; do
  echo "== $eco"
  case $eco in
    homebrew)
      docker run --rm -v "$out:/out" alpine:3.20 sh -c 'mkdir -p /out/homebrew && chmod 777 /out/homebrew'
      sealed --platform linux/amd64 -e DATA=/vol/tool-agreement --entrypoint sh homebrew/brew:latest \
        -c 'sh /ref/homebrew.sh' ;;
    conan)
      docker build -q -t cordon-ref-conan - >/dev/null <<'DOCKERFILE'
FROM python:3.12-slim
RUN pip install --no-cache-dir "conan>=2.20,<3" && conan profile detect >/dev/null 2>&1
DOCKERFILE
      sealed --entrypoint sh cordon-ref-conan -c 'mkdir -p /out/conan && ln -s /vol/tool-agreement /data && python -I /ref/read_conan_py.py'
      # The recipes Conan 2 cannot load (`from conans import ConanFile`), with Conan 1.
      docker build -q -t cordon-ref-conan1 - >/dev/null <<'DOCKERFILE'
FROM python:3.10-slim
RUN pip install --no-cache-dir conan==1.66.0 && conan profile new default --detect >/dev/null 2>&1
DOCKERFILE
      sealed --entrypoint sh cordon-ref-conan1 -c 'ln -s /vol/tool-agreement /data && python -I /ref/read_conan1_py.py' ;;
    hackage)
      docker volume create cordon-cabal-index >/dev/null
      # The package index only, with the network: no project file is read.
      docker run --rm -v cordon-cabal-index:/root/.cabal haskell:9.8 sh -c 'cabal update >/dev/null 2>&1; cabal --version'
      # Each project with the GHC its freeze file pins, by the `base` that GHC ships (the
      # mapping ghcup uses); 9.8 where it pins none.
      for repo in $(docker run --rm -v "$data:/vol:ro" alpine:3.20 sh -c 'cd /vol/tool-agreement/hackage && ls -d */ | tr -d /'); do
        base=$(docker run --rm -v "$data:/vol:ro" alpine:3.20 sh -c "find /vol/tool-agreement/hackage/$repo -name cabal.project.freeze -exec grep -hoE '(^|[ ,])(any\\.)?base ==[0-9.]+' {} + | head -1 | sed 's/.*==//'")
        case $base in
          4.12.*) ghc=8.6.5 ;; 4.14.*) ghc=8.10.7 ;; 4.15.*) ghc=9.0.2 ;; 4.16.*) ghc=9.2.8 ;; 4.17.*) ghc=9.4.8 ;; 4.18.*) ghc=9.6.7 ;; 4.19.*) ghc=9.8.4 ;;
          4.20.*) ghc=9.10.2 ;; 4.21.*) ghc=9.12.2 ;; *) ghc=9.8 ;;
        esac
        echo "  $repo: base ${base:-unpinned}, ghc $ghc"
        # The network stays on here: cabal clones a project's source-repository-packages before
        # solving, and --dry-run builds nothing and runs no Setup.hs, so no project code runs.
        docker run --rm --cap-drop ALL --security-opt no-new-privileges -v "$data:/vol:ro" -v "$out:/out" -v "$here:/ref:ro" \
          -e ONLY="$repo" -v cordon-cabal-index:/root/.cabal --entrypoint sh "haskell:$ghc" -c \
          'mkdir -p /out/hackage && ln -s /vol/tool-agreement /data && ln -sf "$(command -v ghc)" "/usr/local/bin/ghc-$(ghc --numeric-version)" 2>/dev/null; sh /ref/hackage.sh'
      done ;;
  esac
  # Into place, by a container that runs nothing from the repositories.
  docker run --rm -v "$data:/vol" -v "$out:/out:ro" alpine:3.20 sh -c \
    "for d in /out/$eco/*/; do n=\$(basename \$d); mkdir -p /vol/tool-agreement/$eco/\$n/.reference && cp -r \$d. /vol/tool-agreement/$eco/\$n/.reference/; done"
done
