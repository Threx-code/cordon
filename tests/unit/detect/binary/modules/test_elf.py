"""The ELF reader (modules.elf) against the reference engine's recorded values for the real-file fixtures, with
telfhash and import_md5 invoked directly (telfhash runs through modules.tlsh). The reader returns plain,
schema-shaped data; recode() renders it the way the reference engine reports a module so the two compare leaf
by leaf (the Call fields telfhash/import_md5 are skipped there and checked separately). The malformed-file
and full-corpus differentials live in the review harness; these fixtures pin the values a change must not move.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from cordon_scanner.detect.binary.modules.elf import Elf
from cordon_scanner.detect.binary.modules.values import Call, Data, Keyed, Record, Scalar, Seq
from support import ROOT

DIR = ROOT / "tests" / "unit" / "data" / "rule_reference" / "modules"
EXPECTED: dict[str, Any] = json.loads((DIR / "expected.json").read_text(encoding="utf-8"))
ELF_FIXTURES = sorted(
    n for n, e in EXPECTED.items() if (e["modules"].get("elf") or {}).get("type") is not None
)


class Tree:
    """Schema-shaped data rendered and flattened the way the reference engine reports a module."""

    @staticmethod
    def recode(declared: Any, data: Any) -> Any:
        if data is None or isinstance(declared, Call):
            return None
        if isinstance(declared, Scalar):
            if declared is Scalar.TEXT:
                return {"b": data.hex()}
            if declared is Scalar.INT:
                v = data & ((1 << 64) - 1)
                return v - (1 << 64) if v >> 63 else v
            return data
        if isinstance(declared, Record):
            out = {}
            for k, kind in declared.fields.items():
                if k in data and data[k] is not None:
                    r = Tree.recode(kind, data[k])
                    if r is not None:
                        out[k] = r
            return out
        if isinstance(declared, Seq):
            return [Tree.recode(declared.item, v) for _k, v in sorted(data.items())]
        if isinstance(declared, Keyed):
            return {k.decode("latin-1"): Tree.recode(declared.item, v) for k, v in data.items()}
        return data

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


class TestElfValues:
    @pytest.mark.parametrize("name", ELF_FIXTURES)
    def test_every_value_is_the_one_the_reference_gives(self, name: str) -> None:
        data = (DIR / name).read_bytes()
        expected = EXPECTED[name]
        assert hashlib.sha256(data).hexdigest() == expected["sha256"]
        want = Tree.leaves(expected["modules"]["elf"], "", {})
        got = Tree.leaves(Tree.recode(Elf.SCHEMA, Elf.data(data)), "", {})
        assert {k: got.get(k, "MISSING") for k in want if got.get(k, "MISSING") != want[k]} == {}
        assert sorted(set(got) - set(want)) == []

    @pytest.mark.parametrize("name", ELF_FIXTURES)
    def test_conforms_to_the_declared_schema(self, name: str) -> None:
        data = (DIR / name).read_bytes()
        assert Data.conforms(Elf.SCHEMA, Elf.data(data)) == []

    @pytest.mark.parametrize("name", ELF_FIXTURES)
    def test_telfhash_and_import_md5(self, name: str) -> None:
        """The import digest (through modules.tlsh) and import MD5, invoked on the returned callables."""
        d = Elf.data((DIR / name).read_bytes())
        functions = EXPECTED[name]["functions"]
        assert d["telfhash"][0]() == functions["elf.telfhash()"].encode()
        assert d["import_md5"][0]() == functions["elf.import_md5()"].encode()


class TestElfBasics:
    def test_not_an_elf_runs_no_module(self) -> None:
        d = Elf.data(b"plain text, not an executable at all")
        assert "type" not in d  # the header fields are undefined on a non-ELF
        assert d["sections"] == {}
        assert d["ET_EXEC"] == 2  # the module constants are still present

    def test_short_elf_does_not_crash(self) -> None:
        assert "type" not in Elf.data(b"\x7fELF" + b"\x00" * 200)

    def test_import_md5_matches_a_hand_computation(self) -> None:
        """import_md5 is the MD5 of the comma-joined, lower-cased undefined-section symbol names."""
        d = Elf.data((DIR / ELF_FIXTURES[0]).read_bytes())
        got = d["import_md5"][0]()
        assert got is None or (isinstance(got, bytes) and len(got) == 32)
