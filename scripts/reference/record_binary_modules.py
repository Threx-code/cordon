"""Record the reference's pe/elf/dotnet module values for the malformed binary-module corpus.

A maintainer's measurement tool, never part of Cordon: it needs the reference installed (the version is
in tests/unit/data/rule_reference/modules/README.md), and nothing Cordon ships or tests imports it.
It regenerates the malformed set with ``Corpus.mutate`` (tests/conformance/generate/binary_modules.py),
runs the reference over each variant once, and writes the values, with each variant's SHA-256, to
``malformed.json``, which ``test_rule_malformed_replay.py`` replays without the reference.

Run when the fixtures or the mutation scheme change, inside Docker, from the repository root:
    python scripts/reference/record_binary_modules.py \
        tests/unit/data/rule_reference/modules tests/unit/data/rule_reference/modules/malformed.json
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

# Run from the repository root (as below): the mutator is found from there, not from this file.
sys.path.insert(0, str(Path("tests") / "conformance" / "generate"))
# The one mutator, so recording and replay agree; found from the root, so mypy cannot follow it.
from binary_modules import Corpus  # type: ignore[import-not-found]


class Recorder:
    """The reference's module values for each variant of the malformed set."""

    @staticmethod
    def record(fixtures_dir: Path, out_path: Path) -> None:
        """Write the reference's module values for the malformed set into ``out_path``."""
        # The reference; only this measurement tool needs it.
        import yara  # type: ignore[import-not-found]

        rules = yara.compile(
            source='import "pe"\nimport "elf"\nimport "dotnet"\nrule r { condition: true }'
        )
        fixtures = {name: (fixtures_dir / name).read_bytes() for name in Corpus.FIXTURES}
        recorded: dict[str, Any] = {}
        for name, data in sorted(Corpus.mutate(fixtures).items()):
            recorded[name] = {
                "sha256": hashlib.sha256(data).hexdigest(),
                "modules": Recorder._trees(rules, data),
            }
        out_path.write_text(json.dumps(recorded, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        print(f"recorded {len(recorded)} malformed variants to {out_path}")

    @staticmethod
    def _trees(rules: Any, data: bytes) -> Any:
        """The reference's pe/elf/dotnet trees for one file, or None when it leaves a module string the
        reference cannot represent (``modules_callback`` on an undecodable value)."""
        import yara

        trees: dict[str, Any] = {}
        bad: list[int] = []

        def collect(payload: dict[str, Any]) -> int:
            try:
                trees[payload["module"]] = {k: v for k, v in payload.items() if k != "module"}
            except BaseException:  # noqa: BLE001 - an undecodable module string from the reference
                bad.append(1)
            return int(yara.CALLBACK_CONTINUE)

        try:
            rules.match(data=data, modules_callback=collect, timeout=120)
        except (UnicodeDecodeError, SystemError):
            bad.append(1)
        if bad:
            return None
        return Recorder._jsonable(
            {module: trees.get(module, {}) for module in ("pe", "elf", "dotnet")}
        )

    @staticmethod
    def _jsonable(value: object) -> object:
        if isinstance(value, bytes):
            return {"b": value.hex()}
        if isinstance(value, dict):
            return {str(k): Recorder._jsonable(v) for k, v in value.items()}
        if isinstance(value, list):
            return [Recorder._jsonable(v) for v in value]
        return value


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: record_binary_modules.py <fixtures_dir> <malformed.json>")
    Recorder.record(Path(sys.argv[1]), Path(sys.argv[2]))
