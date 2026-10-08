# The self-hosted runner image: `cordon-scanner runner`, with git.
#
# The main image is distroless and has no git, so `docker run ghcr.io/threx-code/cordon runner`
# failed every clone (audit `package.md` PK-04) and self-hosters fell back to images of their own.
# This one carries git and nothing else beyond the scanner. The runner already invokes git with
# hooks, the file protocol, symlinks, submodules and redirects off and `GIT_ALLOW_PROTOCOL=https`
# (`cloud/runner.py`); the environment below sets the same protocol rule for any git it starts.
#
# Built for linux/amd64 and linux/arm64 at release, provenance-attested and cosign-signed like the
# main image.

FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea AS build
WORKDIR /build
COPY pyproject.toml README.md LICENSE NOTICE requirements-build.txt ./
COPY src/ ./src/
RUN python -m pip install --no-cache-dir --require-hashes -r requirements-build.txt \
    && python -m build --wheel --no-isolation --outdir /dist \
    && python -m pip install --no-cache-dir --no-deps --target=/install /dist/*.whl

FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    # The runtime never installs anything: the scanner is copied in from the build stage. The
    # base image's pip carried four high advisories into the runner, found by scanning it.
    && python -m pip uninstall --yes --quiet pip \
    && useradd --uid 10001 --user-group --home-dir /work --create-home --shell /usr/sbin/nologin cordon
COPY --from=build /install /app
ENV PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GIT_ALLOW_PROTOCOL=https \
    GIT_TERMINAL_PROMPT=0 \
    GIT_CONFIG_NOSYSTEM=1
USER 10001:10001
WORKDIR /work
ENTRYPOINT ["python", "-m", "cordon_scanner"]
CMD ["runner"]
