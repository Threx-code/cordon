"""Pick each benign fixture's "hitting" module-function arguments with our reader.

Part of the function differential (see ``function_differential.py``). For each benign fixture it finds,
with our own ``pe`` reader, a real imported DLL and function, a real export name, a real section name, and
an in-section RVA, so the differential can exercise calls that actually resolve against that file. This
uses our reader only -- no reference -- and writes ``args.json`` for ``function_differential.py`` to turn
into calls.

A maintainer's tool, not part of Cordon. Run inside Docker, from the repository root:
    docker run --rm -v "$PWD:/pkg" -w /pkg python:3.12-slim \
      python scripts/reference/function_args.py \
        tests/unit/data/rule_reference/modules /pkg/args.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path("src")))  # run from the repository root, as the README shows
from cordon_scanner.detect.binary.modules.pe import Pe


class FunctionArgs:
    """Per-file arguments that hit something real in the file, discovered with our ``pe`` reader."""

    @staticmethod
    def discover(modules_dir: Path) -> dict[str, dict[str, Any]]:
        """The hitting arguments for every fixture ``expected.json`` names, keyed by file."""
        expected = json.loads((modules_dir / "expected.json").read_text(encoding="utf-8"))
        return {
            name: FunctionArgs._for_file(Pe.data((modules_dir / name).read_bytes()))
            for name in expected
        }

    @staticmethod
    def _for_file(fields: Any) -> dict[str, Any]:
        found: dict[str, Any] = {"is_pe": fields.get("is_pe", 0)}
        for _, library in sorted((fields.get("import_details") or {}).items()):
            named = [fn for _, fn in sorted(library["functions"].items()) if fn.get("name")]
            if named:
                found["imp_dll"] = library["library_name"].decode("latin-1")
                found["imp_fn"] = named[0]["name"].decode("latin-1")
                break
        for _, export in sorted((fields.get("export_details") or {}).items()):
            if export.get("name"):
                found["exp_name"] = export["name"].decode("latin-1")
                break
        sections = sorted((fields.get("sections") or {}).items())
        if sections:
            first = sections[0][1]
            found["sec_name"] = first["name"].decode("latin-1")
            found["in_rva"] = first["virtual_address"]
        return found


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: function_args.py <modules_dir> <args.json>")
    discovered = FunctionArgs.discover(Path(sys.argv[1]))
    Path(sys.argv[2]).write_text(
        json.dumps(discovered, indent=1, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"discovered hitting arguments for {len(discovered)} fixtures")
