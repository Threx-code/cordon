#!/bin/sh
# Writes the SBOM cases from the real saved image (cases/image/real-saved-image/image.tar): Syft's
# CycloneDX and SPDX descriptions of it, which the ingestion cases read back. Syft reads the
# archive; nothing is pulled from a registry or run. The Syft image has no shell, so this is the
# one command to run, from the repository's package directory, with the docker CLI only:
#
#   docker run --rm -v "$PWD/tests/conformance/cases/image:/c" anchore/syft:v1.18.1 \
#     docker-archive:/c/real-saved-image/image.tar \
#     -o cyclonedx-json=/c/real-sbom-cyclonedx/sbom.cdx.json -o spdx-json=/c/real-sbom-spdx/sbom.spdx.json -q
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
docker run --rm -v "$HERE/../cases/image:/c" anchore/syft:v1.18.1 docker-archive:/c/real-saved-image/image.tar \
  -o cyclonedx-json=/c/real-sbom-cyclonedx/sbom.cdx.json -o spdx-json=/c/real-sbom-spdx/sbom.spdx.json -q
