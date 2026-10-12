# Cordon's own detection model: training and evaluation. Built and run only inside Docker; the
# malware samples it reads are opened in memory, never extracted to disk or run, with the network
# off. Every library at an exact version.
FROM python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016
RUN apt-get update -qq && apt-get install -qq -y --no-install-recommends libgomp1 >/dev/null && rm -rf /var/lib/apt/lists/*
RUN python -m pip install --quiet --no-cache-dir \
      numpy==2.1.3 scipy==1.14.1 scikit-learn==1.5.2 lightgbm==4.5.0 joblib==1.4.2 pyzipper==0.3.6 pyyaml==6.0.2
# The package from this checkout -- only what a build reads, never corpus/, build/ or .git -- so
# training reads features with exactly the extractor the scanner ships (cordon_scanner.model).
COPY pyproject.toml README.md LICENSE NOTICE MANIFEST.in /pkg/
COPY src /pkg/src
RUN python -m pip install --quiet --no-cache-dir --no-deps /pkg && rm -rf /pkg
WORKDIR /model
