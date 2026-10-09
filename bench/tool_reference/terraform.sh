#!/bin/sh
# HashiCorp's own static reader of a configuration: required_providers and module calls.
set -u
go install github.com/hashicorp/terraform-config-inspect@latest >/dev/null 2>&1 || exit 2
for repo in /data/terraform/*/; do
  mkdir -p "$repo.reference"; : > "$repo.reference/modules.tsv"; n=0
  find "$repo" -name '*.tf' -not -path '*/.reference/*' -not -path '*/.terraform/*' -exec dirname {} \; | sort -u | while read -r dir; do
    n=$((n + 1))
    rel="${dir#$repo}"; rel="${rel:-.}"
    "$(go env GOPATH)/bin/terraform-config-inspect" --json "$dir" > "$repo.reference/$n.json" 2>/dev/null && printf '%s\t%s.json\n' "$rel" "$n" >> "$repo.reference/modules.tsv"
  done
done
