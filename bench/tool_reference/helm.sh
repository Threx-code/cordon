#!/bin/sh
# `helm dependency list`: what Helm reads from Chart.yaml (and Chart.lock).
set -u
for repo in /data/helm/*/; do
  mkdir -p "$repo.reference"; : > "$repo.reference/helm.txt"
  find "$repo" -name Chart.yaml -not -path '*/.reference/*' | while read -r chart; do
    dir=$(dirname "$chart"); printf '### %s\n' "${dir#$repo}" >> "$repo.reference/helm.txt"
    helm dependency list "$dir" >> "$repo.reference/helm.txt" 2>&1
  done
done
