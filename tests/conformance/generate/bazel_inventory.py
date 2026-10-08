"""Second step of bazel.sh: the authoritative inventory from `bazel mod graph --output=json`, from the
root and from bazel_tools (whose own dependencies the root graph leaves unexpanded). The modules
built into Bazel (bazel_tools, local_config_platform) are part of Bazel, not fetched, and are
excluded with the reason. Run inside Docker only:

    docker run --rm -v "$PWD/tests/conformance:/conformance" python:3.12-slim python /conformance/generate/bazel_inventory.py
"""

import json
from pathlib import Path

CASE = Path("/conformance/cases/bazel/real-bzlmod")
raw = json.loads((CASE / "authoritative.raw.json").read_text(encoding="utf-8"))
found: dict[str, tuple[str, str]] = {}
expanded: set[str] = set()


class ModuleGraph:
    """The modules `bazel mod graph` reaches."""

    @staticmethod
    def walk(node: dict) -> None:
        key = node.get("key", "")
        if key != "<root>":
            name, _, version = key.partition("@")
            found.setdefault(key, (name, node.get("version") or version))
        if key in expanded or "dependencies" not in node:
            return
        expanded.add(key)
        for child in node["dependencies"]:
            ModuleGraph.walk(child)


ModuleGraph.walk(raw["root"])
ModuleGraph.walk(raw["bazel_tools"])
builtin = {"bazel_tools", "local_config_platform"}
packages = sorted(f"{name}@{version}" for name, version in found.values() if name not in builtin)
module = (CASE / "MODULE.bazel").read_text(encoding="utf-8")
overridden = {
    name: "overridden from git or an archive in MODULE.bazel: Bazel's lock holds no registry entry for it; checked in expect.yaml"
    for name in ("bazel_skylib", "rules_pkg")
    if f'module_name = "{name}"' in module
}
(CASE / "authoritative.json").write_text(
    json.dumps(
        {
            "tool": "bazel mod graph --output=json --include_builtin (from the root, and from bazel_tools)",
            "packages": packages,
            "ignore": overridden,
        },
        indent=1,
    )
    + "\n",
    encoding="utf-8",
)
(CASE / "authoritative.raw.json").unlink()
print(packages)
