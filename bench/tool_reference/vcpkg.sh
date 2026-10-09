#!/bin/sh
# `vcpkg format-manifest`: vcpkg's own canonical form of each manifest, written to a copy.
set -u
apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq curl ca-certificates >/dev/null 2>&1
asset=vcpkg-glibc; [ "$(uname -m)" = aarch64 ] && asset=vcpkg-glibc-arm64
curl -fsSLo /usr/local/bin/vcpkg "https://github.com/microsoft/vcpkg-tool/releases/latest/download/$asset" && chmod +x /usr/local/bin/vcpkg || exit 2
mkdir -p /tmp/root && touch /tmp/root/.vcpkg-root && export VCPKG_ROOT=/tmp/root
for repo in /data/vcpkg/*/; do
  mkdir -p "$repo.reference"; : > "$repo.reference/manifests.tsv"; n=0
  find "$repo" -name vcpkg.json -not -path '*/.reference/*' | while read -r file; do
    n=$((n + 1)); cp "$file" "/tmp/m$n.json"
    vcpkg format-manifest "/tmp/m$n.json" >/dev/null 2>&1 && cp "/tmp/m$n.json" "$repo.reference/$n.json" \
      && printf '%s\t%s.json\n' "${file#$repo}" "$n" >> "$repo.reference/manifests.tsv"
  done
done
