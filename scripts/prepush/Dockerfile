# The container `scripts/prepush.sh` checks a commit in: Python 3.12 as CI's lint and self-scan
# jobs use, git for the clone and the history scan, and the `dev` and `attest` extras' tools.
# Built from pyproject.toml alone and tagged with its hash, so it is rebuilt only when the
# dependencies change; the package itself is installed from the commit under check, every run.
FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && git config --system --add safe.directory '*'
COPY pyproject.toml /tmp/pyproject.toml
RUN python - <<'PY' > /tmp/requirements.txt
import tomllib
project = tomllib.load(open("/tmp/pyproject.toml", "rb"))["project"]
extras = project.get("optional-dependencies", {})
for requirement in (*project.get("dependencies", ()), *extras.get("dev", ()), *extras.get("attest", ())):
    print(requirement)
print("pyyaml")
PY
RUN python -m pip install --no-cache-dir --disable-pip-version-check -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt /tmp/pyproject.toml
