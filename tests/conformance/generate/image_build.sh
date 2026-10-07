#!/bin/sh
# Builds generate/image-build/Dockerfile and saves the image as cases/image/real-saved-image/image.tar,
# with the reference the expectations are written from: what Docker reports of the image it
# built (its ID, digests, layers) and the packages the alpine stage installed. Uses the docker CLI
# only; the save is written through a container, never by the host:
#
#   sh tests/conformance/generate/image_build.sh
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
CASE="$HERE/../cases/image/real-saved-image"
TAG=conformance/real-saved-image:1.0
docker build --quiet --platform linux/amd64 -t "$TAG" "$HERE/image-build"
docker save "$TAG" | docker run --rm -i -v "$CASE:/out" alpine:3.20 sh -c 'cat > /out/image.tar && ls -la /out/image.tar'
docker image inspect "$TAG" --format '{{.Id}} {{json .RootFS.Layers}} {{.Os}}/{{.Architecture}}'
docker run --rm --platform linux/amd64 alpine:3.20 sh -c 'apk add --no-cache jq >/dev/null && apk info -v | sort && echo world: && cat /etc/apk/world'
docker image rm "$TAG" >/dev/null
