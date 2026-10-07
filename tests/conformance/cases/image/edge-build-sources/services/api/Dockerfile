# syntax=docker/dockerfile:1.7
ARG PYTHON=3.12
ARG NODE_IMAGE=node:22-bookworm-slim@sha256:4b308f5ccd45aed57f2977257bca304dfef43c99a1b2c3d4e5f6a7b8c9d0e1f2

FROM ${NODE_IMAGE} AS assets
WORKDIR /web
RUN <<EOF
npm ci
npm run build
EOF

FROM --platform=$BUILDPLATFORM ghcr.io/astral-sh/uv:0.5.11@sha256:9d2a5f1e3c4b7a8d6e0f1c2b3a4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d AS uv

FROM python:${PYTHON}-slim
COPY --from=uv /uv /usr/local/bin/uv
COPY --from=assets /web/dist /app/static
COPY --from=quay.io/prometheus/node-exporter:v1.8.2 /bin/node_exporter /usr/local/bin/
ADD --keep-git-dir=true https://github.com/grpc-ecosystem/grpc-health-probe.git#0a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3 /src/health
ADD --checksum=sha256:24454f830cdb571e2c4ad15481119c43b3cafd48dd869a9b2945d1036d1dc68d https://github.com/krallin/tini/releases/download/v0.19.0/tini /tini
RUN uv pip install --system -r /app/requirements.txt
