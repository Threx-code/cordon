#!/bin/sh
# cabal's own solve of each project with a committed freeze file: `cabal build all --dry-run`
# writes the install plan (dist-newstyle/cache/plan.json) without building anything. The package
# index comes from a volume filled beforehand (`cabal update`, which runs no project code). Not
# --offline: that skips cloning a source-repository-package, and the solve then fails on its empty
# checkout. No capabilities, the files read-only, each project solved in a copy.
# A freeze file kept apart from any package (ShellCheck's builders/*/cabal.project.freeze, which
# its build script copies into the root) is solved in the nearest directory above it that holds a
# cabal.project or a .cabal file, as that script does.
set -u
for repo in /data/hackage/${ONLY:-*}/; do
  name=$(basename "$repo"); mkdir -p "/out/hackage/$name"; : > "/out/hackage/$name/plans.tsv"; n=0
  find "$repo" -name cabal.project.freeze -not -path '*/.reference/*' | while read -r freeze; do
    n=$((n + 1)); dir=$(dirname "$freeze"); work=$(mktemp -d)
    project=$dir
    while [ ! -f "$project/cabal.project" ] && [ -z "$(find "$project" -maxdepth 1 -name '*.cabal' | head -1)" ] \
      && [ "${project%/}" != "${repo%/}" ]; do
      project=$(dirname "$project")
    done
    cp -r "$project/." "$work/"
    cp "$freeze" "$work/cabal.project.freeze"
    ( cd "$work" && timeout 900 cabal build all --dry-run > "/out/hackage/$name/$n.log" 2>&1 )
    if [ -f "$work/dist-newstyle/cache/plan.json" ]; then
      cp "$work/dist-newstyle/cache/plan.json" "/out/hackage/$name/$n.json"
      printf '%s\t%s.json\n' "${dir#$repo}" "$n" >> "/out/hackage/$name/plans.tsv"
    fi
    rm -rf "$work"
  done
done
