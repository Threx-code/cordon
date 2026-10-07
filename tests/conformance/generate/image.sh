#!/bin/sh
# Regenerates the real-world image conformance case from Docker's own Compose samples
# (github.com/docker/awesome-compose): their compose.yaml files and the multi-stage Dockerfiles
# their services build, fetched as published at the commit pinned here. Nothing is built or run.
# Run inside Docker only:
#
#   docker run --rm -v "$PWD/tests/conformance:/conformance" curlimages/curl:latest sh /conformance/generate/image.sh
set -eu
COMMIT=30f4b7f6a6c3b0c0ecf4d4efb0de203c48d11562
BASE="https://raw.githubusercontent.com/docker/awesome-compose/$COMMIT"
OUT=/conformance/cases/image/real-compose-samples
rm -rf "$OUT" && mkdir -p "$OUT"
for path in \
  react-express-mongodb/compose.yaml \
  react-express-mongodb/backend/Dockerfile \
  react-express-mongodb/frontend/Dockerfile \
  nginx-golang-mysql/compose.yaml \
  nginx-golang-mysql/backend/Dockerfile \
  wordpress-mysql/compose.yaml \
  prometheus-grafana/compose.yaml; do
  mkdir -p "$OUT/$(dirname "$path")"
  curl -fsSL "$BASE/$path" -o "$OUT/$path"
done
find "$OUT" -type f | sort
echo done
