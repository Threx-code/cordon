"""Second step of homebrew_installed.sh: the authoritative inventory from `brew info --json=v2
--installed`, every installed formula at its installed version. Run inside Docker only:

    docker run --rm -v "$PWD/tests/conformance:/conformance" python:3.12-slim python /conformance/generate/homebrew_inventory.py
"""

import json
from pathlib import Path

CASE = Path("/conformance/cases/homebrew/real-installed")
raw = json.loads((CASE / "authoritative.raw.json").read_text())
packages = sorted(
    f"{formula['name']}@{installed['version']}"
    for formula in raw["formulae"]
    for installed in formula["installed"]
)
(CASE / "authoritative.json").write_text(
    json.dumps({"tool": "brew info --json=v2 --installed", "packages": packages}, indent=1) + "\n"
)
(CASE / "authoritative.raw.json").unlink()
print(len(packages), "packages")
