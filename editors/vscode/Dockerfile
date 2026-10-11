# Builds, tests and packages the extension: `docker build -f editors/vscode/Dockerfile -o out editors/vscode`.
# The marketplace icon (PNG, which both marketplaces require) is rendered here from images/icon.svg,
# so no binary image is ever committed.
FROM node:22-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392 AS build
RUN apt-get update -qq && apt-get install -qq -y --no-install-recommends librsvg2-bin >/dev/null && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
RUN rsvg-convert -w 256 -h 256 images/icon.svg -o images/icon.png \
 && npm ci --ignore-scripts \
 && npm test \
 && npx --yes @vscode/vsce@4.0.0 package --no-dependencies -o /build/cordon.vsix

FROM scratch
COPY --from=build /build/cordon.vsix /
