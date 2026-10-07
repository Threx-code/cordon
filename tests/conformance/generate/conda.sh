#!/bin/sh
# Regenerates the real-world Conda conformance case: conda-lock solves an environment.yml (two
# channels in priority order, a build-string pin, a version range, a pip subsection) for two
# platforms, and renders the linux-64 solution as an explicit export. conda-lock's own lockfile
# reader is the authoritative inventory. Nothing is installed. Run inside Docker only:
#
#   docker run --rm -v "$PWD/tests/conformance:/conformance" condaforge/miniforge3 sh /conformance/generate/conda.sh
set -eu
OUT=/conformance/cases/conda/real-environment
pip install -q conda-lock >/dev/null 2>&1
rm -rf /tmp/k && mkdir -p /tmp/k && cd /tmp/k

cat > environment.yml <<'EOF'
name: analysis
channels:
  - conda-forge
  - bioconda
dependencies:
  - python=3.12
  - numpy>=1.26,<2.1
  - pandas=2.2.*
  - openssl=3.*=*_0
  - samtools=1.20  # [linux]
  - pip
  - pip:
      - requests==2.32.3
      - rich>=13
platforms:
  - linux-64
  - osx-arm64
EOF

conda-lock lock -f environment.yml --lockfile conda-lock.yml > /tmp/lock.log 2>&1 || { tail -20 /tmp/lock.log; exit 1; }
conda-lock render --kind explicit -p linux-64 --filename-template "explicit-{platform}.txt" conda-lock.yml > /tmp/render.log 2>&1 || { tail -20 /tmp/render.log; exit 1; }

rm -rf "$OUT" && mkdir -p "$OUT"
cp environment.yml conda-lock.yml "$OUT/"
cp explicit-linux-64.txt "$OUT/explicit.txt"

python - "$OUT" <<'PY'
import json, sys
from pathlib import Path
from conda_lock.lockfile import parse_conda_lock_file
out = sys.argv[1]
lock = parse_conda_lock_file(Path("conda-lock.yml"))
conda = sorted({f"{p.name}@{p.version}" for p in lock.package if p.manager == "conda"})
pip = sorted({f"{p.name}@{p.version}" for p in lock.package if p.manager == "pip"})
json.dump({
    "tool": "conda_lock.lockfile.parse_conda_lock_file",
    "packages": conda,
    # The pip entries are PyPI packages, compared as PyPI records.
    "other_ecosystems": {"pypi": pip},
}, open(f"{out}/authoritative.json", "w"), indent=1)
print("conda", len(conda), "pip", len(pip))
PY
head -30 conda-lock.yml
head -8 "$OUT/explicit.txt"
echo done
