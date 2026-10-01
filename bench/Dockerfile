# The benchmark image: Cordon from this checkout, and the tools it is compared against, each at a
# pinned version. Built and run only inside Docker; malware samples never touch the host.
FROM python:3.12-slim

ARG TRIVY_VERSION=0.74.0
ARG OSV_SCANNER_VERSION=2.6.0
ARG GUARDDOG_VERSION=3.2.0

RUN apt-get update -qq \
 && apt-get install -qq -y --no-install-recommends ca-certificates curl git unzip p7zip-full >/dev/null \
 && rm -rf /var/lib/apt/lists/*

# Release binaries, verified against the checksums file each project publishes with the release.
RUN set -eu; arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) t=64bit; o=amd64 ;; arm64) t=ARM64; o=arm64 ;; *) echo "unsupported $arch"; exit 1 ;; esac; \
    cd /tmp; \
    curl -fsSLO "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${t}.tar.gz"; \
    curl -fsSLO "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt"; \
    grep " trivy_${TRIVY_VERSION}_Linux-${t}.tar.gz\$" "trivy_${TRIVY_VERSION}_checksums.txt" | sha256sum -c -; \
    tar -xzf "trivy_${TRIVY_VERSION}_Linux-${t}.tar.gz" -C /usr/local/bin trivy; \
    curl -fsSLo osv-scanner "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_${o}"; \
    curl -fsSLO "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_SHA256SUMS"; \
    echo "$(grep " osv-scanner_linux_${o}\$" osv-scanner_SHA256SUMS | cut -d' ' -f1)  osv-scanner" | sha256sum -c -; \
    install -m 0755 osv-scanner /usr/local/bin/osv-scanner; \
    rm -f /tmp/*

RUN python -m pip install --quiet --no-cache-dir "guarddog==${GUARDDOG_VERSION}"

COPY bench/.dist/*.whl /tmp/
RUN python -m pip install --quiet --no-cache-dir --no-deps /tmp/*.whl && rm /tmp/*.whl
COPY bench/ /bench/
WORKDIR /bench
ENTRYPOINT ["python", "/bench/run.py"]
