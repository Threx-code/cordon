"""The shape of a contract schema as a flat map, and the comparison that says whether a newer one is only an addition.

A schema is read into `{path: {type, enum, required, ref}}`, where a path is a property chain (`.decision.reasons[].code`), a branch of
`oneOf`/`anyOf`/`allOf` (`|oneOf0`) or a definition (`#defs/digest`). `compare(old, new)` lists what an additive change may not do inside a
major version: remove a path, retype one, narrow an enum or make a field newly required.

Regenerate the committed baseline, after a deliberate change that is reviewed as a new major or a release:

    python tests/kits/schema_shape.py src/cordon_scanner/contracts/schemas > tests/unit/contracts/schema_baseline.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


class SchemaShape:
    @staticmethod
    def of(schema: Any, path: str = "") -> dict[str, dict[str, Any]]:
        """Every node of a schema, by path."""
        out: dict[str, dict[str, Any]] = {}
        if not isinstance(schema, dict):
            return out
        kind = schema.get("type")
        out[path or "."] = {
            "type": sorted(kind) if isinstance(kind, list) else kind,
            "enum": sorted(map(json.dumps, schema["enum"]))
            if isinstance(schema.get("enum"), list)
            else None,
            "const": json.dumps(schema["const"]) if "const" in schema else None,
            "required": sorted(schema.get("required") or []),
            "ref": schema.get("$ref"),
        }
        for name, sub in (schema.get("properties") or {}).items():
            out |= SchemaShape.of(sub, f"{path}.{name}")
        for name, sub in (schema.get("patternProperties") or {}).items():
            out |= SchemaShape.of(sub, f"{path}.~{name}")
        if isinstance(schema.get("additionalProperties"), dict):
            out |= SchemaShape.of(schema["additionalProperties"], f"{path}.*")
        if isinstance(schema.get("items"), dict):
            out |= SchemaShape.of(schema["items"], f"{path}[]")
        for word in ("oneOf", "anyOf", "allOf"):
            for index, sub in enumerate(schema.get(word) or []):
                out |= SchemaShape.of(sub, f"{path}|{word}{index}")
        for name, sub in (schema.get("$defs") or {}).items():
            out |= SchemaShape.of(sub, f"#defs/{name}")
        return out

    @staticmethod
    def compare(old: dict[str, dict[str, Any]], new: dict[str, dict[str, Any]]) -> list[str]:
        """What the newer shape does that an addition may not, as a short sentence for each."""
        problems = []
        for path, before in sorted(old.items()):
            after = new.get(path)
            if after is None:
                problems.append(f"{path}: removed")
                continue
            if before["type"] != after["type"]:
                problems.append(f"{path}: retyped from {before['type']} to {after['type']}")
            if before["ref"] != after["ref"]:
                problems.append(f"{path}: now points at {after['ref']}, not {before['ref']}")
            if before["const"] != after["const"]:
                problems.append(f"{path}: the fixed value changed")
            if before["enum"] is not None and (
                after["enum"] is None or not set(before["enum"]) <= set(after["enum"])
            ):
                problems.append(f"{path}: an allowed value was removed")
            added = set(after["required"]) - set(before["required"])
            if added:
                problems.append(f"{path}: newly required: {', '.join(sorted(added))}")
        return problems

    @staticmethod
    def folder(directory: Path) -> dict[str, dict[str, dict[str, Any]]]:
        return {
            path.name: SchemaShape.of(json.loads(path.read_text(encoding="utf-8")))
            for path in sorted(directory.glob("*.json"))
        }


if __name__ == "__main__":
    sys.stdout.write(
        json.dumps(SchemaShape.folder(Path(sys.argv[1])), indent=1, sort_keys=True) + "\n"
    )
