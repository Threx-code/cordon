# Cordon's own detection model: training and evaluation. Built and run only inside Docker; the
# malware samples it reads are opened in memory, never extracted to disk or run, with the network
# off. Every library at an exact version and installed only from the hash-locked file beside this
# one (`pip install --require-hashes`, which refuses a requirement that is not pinned and hashed);
# `requirements.in` names the libraries and the lock is made from it with `pip-compile --generate-hashes`.
FROM python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016
RUN apt-get update -qq && apt-get install -qq -y --no-install-recommends libgomp1 >/dev/null && rm -rf /var/lib/apt/lists/*
COPY bench/model/requirements.txt /requirements.txt
RUN python -m pip install --quiet --no-cache-dir --require-hashes -r /requirements.txt
# The package from this checkout -- only what a build reads, never corpus/, build/ or .git -- so
# training reads features with exactly the extractor the scanner ships (cordon_scanner.model).
COPY pyproject.toml README.md LICENSE NOTICE MANIFEST.in /pkg/
COPY src /pkg/src
COPY scripts/backend /pkg/scripts/backend
RUN python -m pip install --quiet --no-cache-dir --no-deps /pkg && rm -rf /pkg
WORKDIR /model
