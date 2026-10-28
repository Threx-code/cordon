"""The malformed binary-module corpus, replayed against the reference engine's recorded values.

The benign reference executables under ``data/rule_reference/modules`` are mutated deterministically
(``tests/conformance/generate/binary_modules.py``: truncations, header bit-flips, field overwrites
with extreme values, a scatter), and our ``pe``/``elf``/``dotnet`` readers are held to the module
trees the reference engine recorded for that set in ``malformed.json``. The mutated bytes are not
shipped -- they regenerate here from the committed fixtures -- so anyone can re-prove this without a
corpus. A per-file digest guards against the mutator drifting from what was recorded. ``expected.json``
and ``test_builtin.py`` are the benign twin of this; here every value also matches the reference,
with no divergence to allow for.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any, ClassVar

import pytest

from cordon_scanner.detect.binary.modules.builtin import Builtin
from cordon_scanner.detect.binary.modules.values import Call, Data, Keyed, Record, Seq
from support import ROOT

sys.path.insert(0, str(ROOT / "tests" / "conformance" / "generate"))
from binary_modules import Corpus  # the one mutator, imported so the replay cannot drift from it

MODULES: Path = ROOT / "tests" / "unit" / "data" / "rule_reference" / "modules"


class Malformed:
    """The recorded reference and the mutated bytes regenerated from the committed benign fixtures."""

    EXPECTED: ClassVar[dict[str, Any]] = json.loads(
        (MODULES / "malformed.json").read_text(encoding="utf-8")
    )
    VARIANTS: ClassVar[dict[str, bytes]] = Corpus.mutate(
        {name: (MODULES / name).read_bytes() for name in Corpus.FIXTURES}
    )

    @staticmethod
    def plain(declared: Any, v: Any) -> Any:
        """Module data as the reference reports it (defined values, sequences as filled slots in
        order, bytes as hex, integers signed 64-bit, functions left out)."""
        if v is None or isinstance(declared, Call):
            return None
        if isinstance(declared, Record):
            out = {k: Malformed.plain(declared.fields[k], x) for k, x in v.items()}
            return {k: x for k, x in out.items() if x is not None}
        if isinstance(declared, Seq):
            return [Malformed.plain(declared.item, v[i]) for i in sorted(v) if v[i] is not None]
        if isinstance(declared, Keyed):
            return {k.decode("latin-1"): Malformed.plain(declared.item, x) for k, x in v.items()}
        if isinstance(v, bytes):
            return {"b": v.hex()}
        return Data.signed(v)

    @staticmethod
    def leaves(v: Any, prefix: str, out: dict[str, Any]) -> dict[str, Any]:
        if isinstance(v, dict) and "b" not in v:
            for k, x in v.items():
                Malformed.leaves(x, f"{prefix}.{k}" if prefix else k, out)
        elif isinstance(v, list):
            for i, x in enumerate(v):
                Malformed.leaves(x, f"{prefix}[{i}]", out)
            out[prefix + "#len"] = len(v)
        else:
            out[prefix] = v
        return out


class TestMalformedReplay:
    def test_the_mutator_regenerates_exactly_the_recorded_bytes(self) -> None:
        # the corpus is regenerated, not shipped; a mutator that drifts from what the reference was
        # recorded over is caught here, by digest, before any value is compared
        assert sorted(Malformed.VARIANTS) == sorted(Malformed.EXPECTED)
        for name, entry in Malformed.EXPECTED.items():
            assert hashlib.sha256(Malformed.VARIANTS[name]).hexdigest() == entry["sha256"], name

    @pytest.mark.parametrize("name", sorted(Malformed.EXPECTED))
    @pytest.mark.parametrize("module", ["pe", "elf", "dotnet"])
    def test_every_value_is_the_one_the_reference_gives(self, name: str, module: str) -> None:
        entry = Malformed.EXPECTED[name]
        if entry["modules"] is None:
            pytest.skip("the reference engine represents no module tree for this file")
        data = Malformed.VARIANTS[name]
        loaded = Builtin.modules()[module]
        assert Data.conforms(loaded.schema, loaded.data(data)) == []
        want = Malformed.leaves(entry["modules"][module], "", {})
        got = Malformed.leaves(Malformed.plain(loaded.schema, loaded.data(data)), "", {})
        assert {k: got.get(k, "MISSING") for k in want if got.get(k, "MISSING") != want[k]} == {}
        assert sorted(set(got) - set(want)) == []
