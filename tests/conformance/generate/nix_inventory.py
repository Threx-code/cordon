"""Second step of nix.sh: the authoritative inventory from `nix flake metadata --json`, which the nix
image (no Python) left in authoritative.raw.json. Each locked node is named by its repository (an
indirect input by the registry name it was asked as) and versioned by its revision. Run inside
Docker only:

    docker run --rm -v "$PWD/tests/conformance:/conformance" python:3.12-slim python /conformance/generate/nix_inventory.py
"""

import json
import re
from pathlib import Path

CASE = Path("/conformance/cases/nix/real-flake")
meta = json.loads((CASE / "authoritative.raw.json").read_text(encoding="utf-8"))
nodes = meta["locks"]["nodes"]
root = meta["locks"]["root"]
packages = []
for key, node in nodes.items():
    if key == root:
        continue
    locked, original = node["locked"], node.get("original", {})
    kind = locked["type"]
    if kind in ("github", "gitlab", "sourcehut"):
        name = f"{locked['owner']}/{locked['repo']}".lower()
    elif kind == "git":
        name = locked["url"].rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
    else:
        url = locked["url"]
        archive = re.match(r"^https://github\.com/([^/]+)/([^/]+)/archive/", url)
        name = (
            f"{archive.group(1)}/{archive.group(2)}".lower() if archive else url.rsplit("/", 1)[-1]
        )
    if original.get("type") == "indirect":
        name = original["id"]
    packages.append(f"{name}@{locked.get('rev') or locked.get('lastModified')}")
(CASE / "authoritative.json").write_text(
    json.dumps(
        {
            "tool": "nix flake metadata --json (the locked input graph)",
            "packages": sorted(packages),
        },
        indent=1,
    )
    + "\n",
    encoding="utf-8",
)
(CASE / "authoritative.raw.json").unlink()
print(sorted(packages))
