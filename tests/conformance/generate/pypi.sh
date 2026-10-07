#!/bin/sh
# Regenerates the real-world PyPI conformance cases: each tool resolves one project and writes its
# own lockfile, and that tool's own export of the lock (read with PyPA's `packaging`) is kept as
# the authoritative inventory. Nothing is built or installed: resolution and export only.
# Run inside Docker only:
#
#   docker run --rm -v "$PWD/tests/conformance:/conformance" python:3.12-slim sh /conformance/generate/pypi.sh
set -eu
OUT=/conformance/cases/pypi
apt-get update -qq >/dev/null && apt-get install -y -qq git >/dev/null
pip install -q pip-tools==7.4.1 poetry==1.8.4 uv==0.5.11 pdm==2.22.1 "hishel<1.0" pipenv==2024.4.0 packaging >/dev/null 2>&1

authoritative() {
  # $1 tool label, $2 requirements-format export, $3 output file
  python - "$1" "$2" "$3" <<'PY'
import json, sys
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
tool, export, out = sys.argv[1:4]
found = set()
logical, pending = [], ""
for raw in open(export):
    line = raw.split(" #", 1)[0].rstrip()
    if line.lstrip().startswith("#") or not line.strip():
        continue
    if line.endswith("\\"):
        pending += line[:-1] + " "
        continue
    logical.append((pending + line).strip()); pending = ""
for line in logical:
    if line.startswith("-"):
        continue
    req = Requirement(line.split(" --hash", 1)[0])
    pins = [s.version for s in req.specifier if s.operator == "=="]
    if pins:
        found.add(f"{canonicalize_name(req.name)}@{pins[0]}")
json.dump({"tool": tool, "packages": sorted(found)}, open(out, "w"), indent=1)
PY
}

project() {
  rm -rf "$1" && mkdir -p "$1" && cd "$1"
  cat > pyproject.toml <<'EOF'
[project]
name = "conformance-app"
version = "1.0.0"
requires-python = ">=3.9"
dependencies = [
  "requests[socks]==2.32.3",
  "colorama==0.4.6; sys_platform == 'win32'",
  "packaging>=24.0",
]

[project.optional-dependencies]
yaml = ["pyyaml==6.0.2"]

[dependency-groups]
test = ["iniconfig==2.0.0"]

[build-system]
requires = ["hatchling==1.25.0"]
build-backend = "hatchling.build"
EOF
}

# pip-tools: requirements.in -> requirements.txt with hashes and `# via` annotations.
rm -rf /tmp/pt && mkdir -p /tmp/pt && cd /tmp/pt
printf 'requests[socks]==2.32.3\ncolorama==0.4.6 ; sys_platform == "win32"\npackaging>=24.0\n-c constraints.txt\n' > requirements.in
printf 'packaging==24.2\n' > constraints.txt
pip-compile -q --generate-hashes --strip-extras requirements.in -o requirements.lock.txt
mkdir -p "$OUT/real-pip-tools" && rm -f "$OUT/real-pip-tools/requirements.txt"
cp requirements.in requirements.lock.txt constraints.txt "$OUT/real-pip-tools/"
authoritative "packaging.Requirement over the pip-compile output" requirements.lock.txt "$OUT/real-pip-tools/authoritative.json"

# Poetry 1.8.
project /tmp/poetry
cat >> pyproject.toml <<'EOF'

[tool.poetry]
name = "conformance-app"
version = "1.0.0"
description = ""
authors = ["Conformance <conformance@example.invalid>"]
package-mode = false

[tool.poetry.dependencies]
python = ">=3.9"
requests = {version = "2.32.3", extras = ["socks"]}
colorama = {version = "0.4.6", markers = "sys_platform == 'win32'"}
packaging = ">=24.0"

[tool.poetry.group.test.dependencies]
iniconfig = "2.0.0"
EOF
poetry lock -q --no-interaction
poetry export -q --without-hashes --with test -f requirements.txt -o /tmp/poetry-export.txt 2>/dev/null || poetry export --without-hashes --with test -f requirements.txt > /tmp/poetry-export.txt
mkdir -p "$OUT/real-poetry"
cp pyproject.toml poetry.lock "$OUT/real-poetry/"
authoritative "poetry export --with test" /tmp/poetry-export.txt "$OUT/real-poetry/authoritative.json"

# uv.
project /tmp/uv
uv lock -q
uv export -q --all-groups --all-extras --no-hashes --no-emit-project -o /tmp/uv-export.txt
mkdir -p "$OUT/real-uv"
cp pyproject.toml uv.lock "$OUT/real-uv/"
authoritative "uv export --all-groups --all-extras" /tmp/uv-export.txt "$OUT/real-uv/authoritative.json"

# PDM.
project /tmp/pdm
pdm lock -q -G :all 2>/dev/null || pdm lock -G :all
pdm export -G :all --no-hashes -o /tmp/pdm-export.txt 2>/dev/null
mkdir -p "$OUT/real-pdm"
cp pyproject.toml pdm.lock "$OUT/real-pdm/"
authoritative "pdm export -G :all" /tmp/pdm-export.txt "$OUT/real-pdm/authoritative.json"

# Pipenv.
rm -rf /tmp/pipenv && mkdir -p /tmp/pipenv && cd /tmp/pipenv
cat > Pipfile <<'EOF'
[[source]]
url = "https://pypi.org/simple"
verify_ssl = true
name = "pypi"

[packages]
requests = {version = "==2.32.3", extras = ["socks"]}
colorama = {version = "==0.4.6", markers = "sys_platform == 'win32'"}

[dev-packages]
iniconfig = "==2.0.0"

[requires]
python_version = "3.12"
EOF
PIPENV_VENV_IN_PROJECT=1 pipenv lock >/dev/null 2>&1
pipenv requirements --dev > /tmp/pipenv-export.txt
mkdir -p "$OUT/real-pipenv"
cp Pipfile Pipfile.lock "$OUT/real-pipenv/"
authoritative "pipenv requirements --dev" /tmp/pipenv-export.txt "$OUT/real-pipenv/authoritative.json"

# A uv workspace: a root and two members, one depending on the other, sharing one uv.lock.
rm -rf /tmp/uvws && mkdir -p /tmp/uvws/packages/core /tmp/uvws/packages/api && cd /tmp/uvws
cat > pyproject.toml <<'EOF'
[project]
name = "workspace-root"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = ["api"]

[tool.uv.workspace]
members = ["packages/*"]

[tool.uv.sources]
api = { workspace = true }
EOF
cat > packages/core/pyproject.toml <<'EOF'
[project]
name = "core"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = ["attrs==24.2.0"]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
EOF
cat > packages/api/pyproject.toml <<'EOF'
[project]
name = "api"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = ["core", "idna==3.10"]

[tool.uv.sources]
core = { workspace = true }

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
EOF
uv lock -q
uv export -q --all-packages --no-hashes --no-emit-workspace -o /tmp/uvws-export.txt
mkdir -p "$OUT/real-uv-workspace/packages/core" "$OUT/real-uv-workspace/packages/api"
cp pyproject.toml uv.lock "$OUT/real-uv-workspace/"
cp packages/core/pyproject.toml "$OUT/real-uv-workspace/packages/core/"
cp packages/api/pyproject.toml "$OUT/real-uv-workspace/packages/api/"
authoritative "uv export --all-packages --no-emit-workspace" /tmp/uvws-export.txt "$OUT/real-uv-workspace/authoritative.json"

# pip-tools in a requirements/ directory: requirements/base.in compiled to requirements/base.txt.
rm -rf /tmp/ptdir && mkdir -p /tmp/ptdir/requirements && cd /tmp/ptdir
printf 'idna==3.10\nattrs>=24\n' > requirements/base.in
pip-compile -q --generate-hashes requirements/base.in -o requirements/base.txt
mkdir -p "$OUT/regression-requirements-dir/requirements"
cp requirements/base.in requirements/base.txt "$OUT/regression-requirements-dir/requirements/"
authoritative "packaging.Requirement over the pip-compile output" requirements/base.txt "$OUT/regression-requirements-dir/authoritative.json"

echo done
