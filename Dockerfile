# Cordon container image.
#
# Two stages so the runtime image carries no build tooling, no package manager
# and no shell. A security scanner that ships a fat image is asking its users to
# accept a larger attack surface than the thing it is scanning.

FROM python:3.12-slim@sha256:2b2c3a1c19cb96b8ba1f0e7f1e4bdcf3e6b7c1a9f0e1d2c3b4a5968778695a4b AS build

WORKDIR /build
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src/ ./src/

RUN python -m pip install --no-cache-dir --upgrade pip build \
    && python -m build --wheel --outdir /dist

FROM gcr.io/distroless/python3-debian12:nonroot@sha256:0000000000000000000000000000000000000000000000000000000000000000

# Zero third-party runtime dependencies, so this copies exactly one wheel and
# nothing transitive. That is the practical benefit of the constraint: the
# image's software bill of materials is one line long.
COPY --from=build /dist/*.whl /tmp/
COPY --from=build /build/src /app/src

ENV PYTHONPATH=/app/src \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Non-root, and no shell in the image at all. There is nothing to drop into if
# something goes wrong, which is the point.
USER nonroot:nonroot
WORKDIR /scan

ENTRYPOINT ["python", "-m", "cordon.cli.main"]
CMD ["scan", "/scan"]
