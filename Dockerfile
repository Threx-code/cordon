# Cordon container image.
#
# Two stages so the runtime image carries no build tooling, no package manager
# and no shell. A security scanner that ships a fat image is asking its users to
# accept a larger attack surface than the thing it is scanning.

FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea AS build

WORKDIR /build
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src/ ./src/

# Installed into one flat directory rather than a versioned prefix. The runtime
# image is distroless Python 3.11 while the build image is 3.12, so
# `--prefix=/install` produced `lib/python3.12/site-packages`, which the runtime
# interpreter does not look in -- the image built and then reported "No module
# named cordon".
#
# A flat target plus PYTHONPATH is version-independent, and safe here only
# because the package has zero runtime dependencies: there is nothing
# transitive, and nothing compiled against a specific interpreter.
RUN python -m pip install --no-cache-dir --upgrade pip build \
    && python -m build --wheel --outdir /dist \
    && python -m pip install --no-cache-dir --no-deps --target=/install /dist/*.whl

# Both base images are pinned by digest, and both digests are real. The runtime
# line previously carried sixty-four zeros, so `docker build` failed outright
# and every CI template referencing the resulting image pointed at something
# that could not exist. A fabricated digest is worse than an honest tag: it
# reads as a supply-chain control while being a build error.
FROM gcr.io/distroless/python3-debian12:nonroot@sha256:7d1042ce588ab97019fe95c24ffca7bc5a82ccdac572511d5e09bda4435c89c5

# Zero third-party runtime dependencies, so this copies exactly one wheel and
# nothing transitive. That is the practical benefit of the constraint: the
# image's software bill of materials is one line long.
# The wheel the build stage produces is installed, rather than copied to /tmp
# and abandoned while the runtime adds src/ to PYTHONPATH. The two-stage build's
# whole purpose is that the runtime image contains an installed artefact and not
# loose source.
COPY --from=build /install /app

ENV PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Non-root, and no shell in the image at all. There is nothing to drop into if
# something goes wrong, which is the point.
USER nonroot:nonroot
WORKDIR /scan

ENTRYPOINT ["python", "-m", "cordon"]
CMD ["scan", "/scan"]
