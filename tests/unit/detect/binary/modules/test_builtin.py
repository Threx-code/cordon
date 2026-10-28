"""The `pe`, `elf` and `dotnet` modules as rules see them, and the signature readers under them.

The field-by-field differentials against the reference engine ran over every real executable in
the corpus; these tests hold what they settled, so a change that breaks one is caught here. The
real-file values are read through the engine's own module table (`modules.builtin`), as a scan reads
them, and compared with the reference's recorded values
(`tests/unit/data/rule_reference/modules/README.md` says where those come from).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, ClassVar

import pytest

from cordon_scanner.detect.binary.modules.builtin import Builtin
from cordon_scanner.detect.binary.modules.values import Call, Data, Keyed, Record, Seq
from cordon_scanner.detect.binary.rule_engine.lang import Rules
from support import ROOT


class TestIntegers:
    def test_module_integers_are_signed_64_bit(self) -> None:
        assert Data.signed((1 << 64) - 7744) == -7744
        assert Data.signed(5) == 5
        assert Data.signed(True) is True

    def test_not_a_pe_is_zero_not_undefined(self) -> None:
        assert Rules.compile('import "pe" rule r { condition: pe.is_pe == 0 }').match(b"plain text")
        assert Rules.compile(
            'import "dotnet" rule r { condition: not defined dotnet.is_dotnet }'
        ).match(b"x")

    def test_function_signatures_type_check_as_declared(self) -> None:
        rules = Rules.compile(
            'import "pe" rule r { condition: pe.imphash() == "" or pe.imports(pe.IMPORT_ANY, "k.dll", "f") '
            'or pe.import_rva("k.dll", "f") == 0 or pe.exports_index(/x/) == 0 }'
        )
        assert not rules.match(b"not a pe")


class RealFiles:
    """The fixtures under `data/rule_reference/modules` and the reference's values for them."""

    DIR: ClassVar[Path] = ROOT / "tests" / "unit" / "data" / "rule_reference" / "modules"
    EXPECTED: ClassVar[dict[str, Any]] = json.loads(
        (DIR / "expected.json").read_text(encoding="utf-8")
    )

    @staticmethod
    def plain(declared: Any, v: Any) -> Any:
        """Module data as the reference reports it: defined values only, sequences as the slots
        a file filled (in order), bytes as hex, integers signed 64-bit, functions left out."""
        if v is None or isinstance(declared, Call):
            return None
        if isinstance(declared, Record):
            out = {k: RealFiles.plain(declared.fields[k], x) for k, x in v.items()}
            return {k: x for k, x in out.items() if x is not None}
        if isinstance(declared, Seq):
            return [RealFiles.plain(declared.item, v[i]) for i in sorted(v) if v[i] is not None]
        if isinstance(declared, Keyed):
            return {k.decode("latin-1"): RealFiles.plain(declared.item, x) for k, x in v.items()}
        if isinstance(v, bytes):
            return {"b": v.hex()}
        return Data.signed(v)

    @staticmethod
    def leaves(v: Any, prefix: str, out: dict[str, Any]) -> dict[str, Any]:
        if isinstance(v, dict) and "b" not in v:
            for k, x in v.items():
                RealFiles.leaves(x, f"{prefix}.{k}" if prefix else k, out)
        elif isinstance(v, list):
            for i, x in enumerate(v):
                RealFiles.leaves(x, f"{prefix}[{i}]", out)
            out[prefix + "#len"] = len(v)
        else:
            out[prefix] = v
        return out


class TestRealFiles:
    @pytest.mark.parametrize("name", sorted(RealFiles.EXPECTED))
    @pytest.mark.parametrize("module", ["pe", "elf", "dotnet"])
    def test_every_value_is_the_one_the_reference_gives(self, name: str, module: str) -> None:
        data = (RealFiles.DIR / name).read_bytes()
        expected = RealFiles.EXPECTED[name]
        assert hashlib.sha256(data).hexdigest() == expected["sha256"]
        loaded = Builtin.modules()[module]
        assert Data.conforms(loaded.schema, loaded.data(data)) == []
        want = RealFiles.leaves(expected["modules"][module], "", {})
        got = RealFiles.leaves(RealFiles.plain(loaded.schema, loaded.data(data)), "", {})
        assert {k: got.get(k, "MISSING") for k in want if got.get(k, "MISSING") != want[k]} == {}
        assert sorted(set(got) - set(want)) == []

    @pytest.mark.parametrize("name", sorted(RealFiles.EXPECTED))
    def test_every_function_returns_what_the_reference_returns(self, name: str) -> None:
        data = (RealFiles.DIR / name).read_bytes()
        for call, value in RealFiles.EXPECTED[name]["functions"].items():
            literal = value if value.lstrip("-").isdigit() else '"' + value + '"'
            rule = f'import "pe"\nimport "elf"\nrule r {{ condition: {call} == {literal} }}'
            assert Rules.compile(rule).match(data), call
