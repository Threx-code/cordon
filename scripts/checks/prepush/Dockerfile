# The container `scripts/checks/prepush.sh` checks a commit in: Python 3.12 as CI's lint and self-scan
# jobs use, git for the clone and the history scan, and CI's locked development toolchain.
# Tagged with the lock file's hash, so it is rebuilt only when the toolchain changes; the package
# itself (which has no dependencies) is installed from the commit under check, every run.
FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && git config --system --add safe.directory '*'
# The development toolchain is hash-locked in ci/dev-requirements.txt, as CI installs it; pyyaml
# is the parity checker's own, to read the workflows.
COPY ci/dev-requirements.txt /tmp/dev-requirements.txt
RUN python -m pip install --no-cache-dir --disable-pip-version-check --require-hashes \
        -r /tmp/dev-requirements.txt \
    && python -m pip install --no-cache-dir --disable-pip-version-check pyyaml \
    && rm /tmp/dev-requirements.txt
