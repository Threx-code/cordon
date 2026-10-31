"""Record the reference engines' module values for the test fixtures: YARA's from `yara -D`, YARA-X's
from `yr dump --output-format=json`.

A maintainer's measurement tool, never part of Cordon: it reads the text dumps `yara -D` (YARA 4.5.8,
built from source in the reference image) writes for a rule importing the module, one file per fixture,
and records them as JSON with each fixture's SHA-256, which `test_yara_dumps.py` replays without the
reference. Run inside Docker, from the repository root, after producing the dumps:

    for f in tests/unit/data/rule_reference/yara_tests/*; do yara -D macho.yar "$f" > dumps/$(basename "$f").macho.yara.txt; done
    python scripts/reference/record_module_dumps.py dumps tests/unit/data/rule_reference/yara_tests \\
        tests/unit/data/rule_reference/yara_tests/reference-4.5.8.json

A dump line is `name = value` (an integer, or a C-escaped string; `YR_UNDEFINED` is left out), `name`
for a structure or array, `[i]` for an array item, nested by tabs.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


class Dump:
    """`yara -D` text as a tree: structures and arrays as dicts (arrays keyed by index), strings as
    bytes rendered hex under `b`, integers as they print."""

    @staticmethod
    def unescape(text: str) -> bytes:
        out = bytearray()
        i = 0
        while i < len(text):
            c = text[i]
            if c == "\\" and i + 1 < len(text):
                n = text[i + 1]
                if n == "x":
                    out += bytes([int(text[i + 2 : i + 4], 16)])
                    i += 4
                    continue
                out += {"n": b"\n", "t": b"\t", "r": b"\r", "\\": b"\\", '"': b'"'}.get(
                    n, n.encode()
                )
                i += 2
                continue
            out += c.encode("utf-8")
            i += 1
        return bytes(out)

    @staticmethod
    def parse(text: str) -> dict[str, Any]:
        root: dict[str, Any] = {}
        stack: list[tuple[int, dict[str, Any]]] = [(-1, root)]
        for line in text.splitlines():
            if not line.strip():
                continue
            depth = len(line) - len(line.lstrip("\t"))
            body = line.strip()
            while stack and stack[-1][0] >= depth:
                stack.pop()
            parent = stack[-1][1]
            item = re.match(r"^\[(\d+)\]$", body)
            if item:
                node: dict[str, Any] = {}
                parent[item.group(1)] = node
                stack.append((depth, node))
                continue
            if " = " in body:
                key, value = body.split(" = ", 1)
                if value == "YR_UNDEFINED":
                    continue
                if value.startswith('"'):
                    parent[key] = {"b": Dump.unescape(value[1:-1]).hex()}
                else:
                    parent[key] = int(value)
                continue
            node = {}
            parent[body] = node
            stack.append((depth, node))
        return root

    @staticmethod
    def leaves(v: Any, prefix: str, out: dict[str, Any]) -> dict[str, Any]:
        """Every leaf by its path; an empty structure or array is a leaf of its own."""
        if isinstance(v, dict) and "b" not in v:
            if not v:
                out[prefix + "#empty"] = True
            for k, x in v.items():
                Dump.leaves(x, f"{prefix}.{k}", out)
        else:
            out[prefix] = v
        return out

    @staticmethod
    def digest(leaves: dict[str, Any]) -> str:
        """One hash over the sorted leaves, so a large dump is pinned without being stored."""
        text = json.dumps(sorted(leaves.items()), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(text.encode("utf-8")).hexdigest()


def main(dumps: Path, fixtures: Path, out: Path) -> None:
    record: dict[str, Any] = {}
    for path in sorted(dumps.glob("*.json")):  # yr's JSON dumps (`yr dump --output-format=json`)
        name = path.name[:-5]
        data = (fixtures / name).read_bytes()
        dump = json.loads(path.read_text(encoding="utf-8"))
        record[name] = {"sha256": hashlib.sha256(data).hexdigest(), "modules": dump}
    for path in sorted(dumps.glob("*.yara.txt")):
        if path.stat().st_size == 0:
            continue  # the reference gave no dump (it was killed on a crafted file)
        name, module = path.name.rsplit(".", 3)[0], path.name.rsplit(".", 3)[1]
        data = (fixtures / name).read_bytes()
        entry = record.setdefault(name, {"sha256": hashlib.sha256(data).hexdigest(), "modules": {}})
        tree = Dump.parse(path.read_text(encoding="utf-8", errors="replace")).get(module, {})
        if name.startswith(
            "shared-"
        ):  # a crafted file of thousands of entries: its leaves as a digest
            leaves = Dump.leaves(tree, "", {})
            entry["modules"][module] = {
                "summary": True,
                "number_of_methods": tree.get("number_of_methods"),
                "leaf_count": len(leaves),
                "leaf_digest": Dump.digest(leaves),
            }
        else:
            entry["modules"][module] = tree
    out.write_text(json.dumps(record, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"{len(record)} fixtures recorded to {out}")


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))
