# Cordon's model server: `docker build -f model-server/Dockerfile -t cordon-model-server .` from
# the package root. Runs as an unprivileged user; the bundle, its public key and the token hashes
# are mounted read-only at run time, never baked in.
FROM python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016
RUN apt-get update -qq && apt-get install -qq -y --no-install-recommends libgomp1 >/dev/null \
 && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml README.md LICENSE NOTICE MANIFEST.in /src/scanner/
COPY src /src/scanner/src
COPY model-server /src/model-server
RUN python -m pip install --quiet --no-cache-dir --no-deps /src/scanner \
 && python -m pip install --quiet --no-cache-dir /src/model-server \
 && rm -rf /src \
 && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin cordon
USER 10001
ENV CORDON_MODEL_PORT=8443 PYTHONDONTWRITEBYTECODE=1
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=6s --retries=3 CMD ["python", "-m", "cordon_model_server.health"]
ENTRYPOINT ["cordon-model-server"]
CMD ["serve", "--bundle", "/bundle", "--public-key", "/keys/model.pub", "--tokens-file", "/keys/tokens.sha256", "--host", "0.0.0.0", "--port", "8443", "--tls-cert", "/tls/tls.crt", "--tls-key", "/tls/tls.key"]
