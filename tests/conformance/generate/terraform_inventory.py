"""Second step of terraform.sh: the authoritative inventory from Terraform's provider selections and
module manifest, which the terraform image (no Python) left in authoritative.raw.json. Run inside
Docker only:

    docker run --rm -v "$PWD/tests/conformance:/conformance" python:3.12-slim python /conformance/generate/terraform_inventory.py
"""

import json
import re
from pathlib import Path

CASE = Path("/conformance/cases/terraform/real-root-module")
raw = (CASE / "authoritative.raw.json").read_text()
marker = '"modules_json": '
modules = json.loads(raw[raw.index(marker) + len(marker) :].rstrip().rstrip("}").rstrip())
packages = re.findall(r'"([^"@]+@[^"]+)"', raw[: raw.index(marker)])
ignore = {}
for module in modules["Modules"]:
    source = module.get("Source", "")
    if source.startswith("registry.terraform.io/"):
        name = source.removeprefix("registry.terraform.io/")
        packages.append(f"{name}@{module['Version']}")
        # Compared in expect.yaml: the inventory comparison is of what the lockfile resolved, and
        # Terraform's lock holds providers only.
        ignore[name] = (
            "a module: Terraform locks providers, not modules; its exact version is checked in expect.yaml"
        )
    elif source.startswith("git::"):
        # Terraform records no version for a module fetched from git: only the ref it asked for.
        ignore[source.split("?")[0].rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")] = (
            "a module fetched from git at a ref: Terraform records no version for it"
        )
(CASE / "authoritative.json").write_text(
    json.dumps(
        {
            "tool": "terraform version -json (provider selections) and .terraform/modules/modules.json",
            "packages": sorted(packages),
            "ignore": ignore,
            # Providers are recorded as tools, and the provider selections are exactly those.
            "lists_tools": True,
        },
        indent=1,
    )
    + "\n"
)
(CASE / "authoritative.raw.json").unlink()
print(sorted(packages), ignore)
