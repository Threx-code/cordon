"""Regenerate action/requirements-attest.txt: the hash-locked signing stack templates install.

Run in a container, never on a workstation's own Python:

    docker run --rm -v "$PWD":/src -w /src python:3.12-slim \\
        sh -c "pip install -q pip-tools && python scripts/lock_attest_requirements.py"

Python 3.12 is the interpreter every template sets up, and pip-compile records the hash of every
file PyPI publishes for each pinned version, so the lock installs on every platform those wheels
cover. The range comes from the `attest` extra in pyproject.toml, so the lock and the extra agree.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "action" / "requirements-attest.txt"


class AttestLock:
    HEADER = (LOCK.read_text(encoding="utf-8").split("\n\n", 1)[0] + "\n") if LOCK.exists() else ""

    @staticmethod
    def sigstore_range() -> str:
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        found = re.search(r'"(sigstore[^"]*)"', text.split("attest = [", 1)[1])
        if not found:
            raise SystemExit("pyproject.toml names no sigstore range in the attest extra")
        return found.group(1)

    @staticmethod
    def main() -> int:
        with tempfile.TemporaryDirectory() as work:
            source = Path(work) / "attest.in"
            source.write_text(AttestLock.sigstore_range() + "\n", encoding="utf-8")
            out = Path(work) / "attest.txt"
            subprocess.run(  # noqa: S603 - fixed arguments, a temporary file, inside a container
                [
                    sys.executable,
                    "-m",
                    "piptools",
                    "compile",
                    "-q",
                    "--generate-hashes",
                    "--allow-unsafe",
                    "--strip-extras",
                    "--no-header",
                    "--output-file",
                    str(out),
                    str(source),
                ],
                check=True,
            )
            LOCK.write_text(AttestLock.HEADER + out.read_text(encoding="utf-8"), encoding="utf-8")
        return 0


if __name__ == "__main__":
    raise SystemExit(AttestLock.main())
