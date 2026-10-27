"""The PE reader (rule_pe) against yara-python's recorded values for the real-file fixtures, plus the
module functions invoked directly. The malformed-file and full-corpus differentials live in the review
harness; these fixtures pin the values a change must not move.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from cordon_scanner.detect.binary.rule_pe import Pe
from cordon_scanner.detect.binary.rule_values import (
    Array,
    Dictionary,
    Function,
    Struct,
    TypedUndefined,
    Values,
)
from support import ROOT

DIR = ROOT / "tests" / "unit" / "data" / "rule_reference" / "modules"
EXPECTED: dict[str, Any] = json.loads((DIR / "expected.json").read_text(encoding="utf-8"))
PE_FIXTURES = sorted(n for n, e in EXPECTED.items() if (e["modules"].get("pe") or {}).get("is_pe"))


class Tree:
    """A module tree flattened the way yara-python reports it, for leaf-by-leaf comparison."""

    @staticmethod
    def plain(v: Any) -> Any:
        if isinstance(v, Struct):
            out = {
                k: Tree.plain(x)
                for k, x in v.fields.items()
                if not isinstance(x, (Function, TypedUndefined))
            }
            return {k: x for k, x in out.items() if x is not None}
        if isinstance(v, Array):
            return [Tree.plain(x) for x in v.values()]
        if isinstance(v, Dictionary):
            return {k.decode("latin-1"): Tree.plain(x) for k, x in v.items.items()}
        if isinstance(v, (TypedUndefined, Function)):
            return None
        if isinstance(v, bytes):
            return {"b": v.hex()}
        return Values.int64(v)

    @staticmethod
    def leaves(v: Any, prefix: str, out: dict[str, Any]) -> dict[str, Any]:
        if isinstance(v, dict) and "b" not in v:
            for k, x in v.items():
                Tree.leaves(x, f"{prefix}.{k}" if prefix else k, out)
        elif isinstance(v, list):
            for i, x in enumerate(v):
                Tree.leaves(x, f"{prefix}[{i}]", out)
            out[prefix + "#len"] = len(v)
        else:
            out[prefix] = v
        return out


class TestPeValues:
    @pytest.mark.parametrize("name", PE_FIXTURES)
    def test_every_value_is_the_one_yara_gives(self, name: str) -> None:
        data = (DIR / name).read_bytes()
        expected = EXPECTED[name]
        assert hashlib.sha256(data).hexdigest() == expected["sha256"]
        want = Tree.leaves(expected["modules"]["pe"], "", {})
        got = Tree.leaves(Tree.plain(Pe.module(data)), "", {})
        assert {k: got.get(k, "MISSING") for k in want if got.get(k, "MISSING") != want[k]} == {}
        assert sorted(set(got) - set(want)) == []


class TestPeBasics:
    def test_not_a_pe_is_zero_not_undefined(self) -> None:
        root = Pe.module(b"plain text, not an executable at all")
        assert root.fields["is_pe"] == 0
        assert isinstance(root.fields["machine"], TypedUndefined)

    def test_short_mz_does_not_crash(self) -> None:
        assert Pe.module(b"MZ" + b"\x00" * 100).fields["is_pe"] == 0

    def test_functions_resolve_and_run(self) -> None:
        """Invoke each non-regex overload so the function layer is exercised on a real PE."""
        data = (DIR / PE_FIXTURES[0]).read_bytes()
        f = Pe.module(data).fields
        for name in ("imphash", "is_dll", "is_32bit", "is_64bit", "calculate_checksum"):
            call, _ = f[name].resolve(())
            assert call() is not None
        assert isinstance(f["imphash"].resolve(())[0](), bytes)
        assert f["imports"].resolve(("str",))[0](b"kernel32.dll") >= 0
        assert f["imports"].resolve(("str", "str"))[0](b"kernel32.dll", b"CreateFileW") in (0, 1)
        assert f["imports"].resolve(("int", "str"))[0](3, b"kernel32.dll") >= 0
        assert f["exports"].resolve(("str",))[0](b"nope") in (0, 1)
        assert f["exports"].resolve(("int",))[0](1) in (0, 1)
        assert f["exports_index"].resolve(("str",))[0](b"nope") is not None
        assert f["section_index"].resolve(("str",))[0](b".text") is not None
        assert f["section_index"].resolve(("int",))[0](0) is not None
        assert f["import_rva"].resolve(("str", "str"))[0](b"k", b"f") is not None
        assert f["rva_to_offset"].resolve(("int",))[0](0x1000) is not None
        assert f["locale"].resolve(("int",))[0](0x409) in (0, 1)
        assert f["language"].resolve(("int",))[0](9) in (0, 1)
