"""The ELF reader (rule_elf) against yara-python's recorded values for the real-file fixtures, with
telfhash and import_md5 invoked directly (telfhash runs through rule_tlsh). The malformed-file and
full-corpus differentials live in the review harness; these fixtures pin the values a change must not move.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from cordon_scanner.detect.binary.rule_elf import Elf
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
ELF_FIXTURES = sorted(
    n for n, e in EXPECTED.items() if (e["modules"].get("elf") or {}).get("type") is not None
)


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


class TestElfValues:
    @pytest.mark.parametrize("name", ELF_FIXTURES)
    def test_every_value_is_the_one_yara_gives(self, name: str) -> None:
        data = (DIR / name).read_bytes()
        expected = EXPECTED[name]
        assert hashlib.sha256(data).hexdigest() == expected["sha256"]
        want = Tree.leaves(expected["modules"]["elf"], "", {})
        got = Tree.leaves(Tree.plain(Elf.module(data)), "", {})
        assert {k: got.get(k, "MISSING") for k in want if got.get(k, "MISSING") != want[k]} == {}
        assert sorted(set(got) - set(want)) == []

    @pytest.mark.parametrize("name", ELF_FIXTURES)
    def test_telfhash_and_import_md5(self, name: str) -> None:
        """The import digest (through rule_tlsh) and import MD5, invoked on the tree."""
        data = (DIR / name).read_bytes()
        f = Elf.module(data).fields
        functions = EXPECTED[name]["functions"]
        got_telfhash = f["telfhash"].resolve(())[0]()
        got_md5 = f["import_md5"].resolve(())[0]()
        assert got_telfhash == functions["elf.telfhash()"].encode()
        assert got_md5 == functions["elf.import_md5()"].encode()


class TestElfBasics:
    def test_not_an_elf_is_undefined(self) -> None:
        root = Elf.module(b"plain text, not an executable at all")
        assert isinstance(root.fields["type"], TypedUndefined)

    def test_short_elf_does_not_crash(self) -> None:
        assert isinstance(Elf.module(b"\x7fELF" + b"\x00" * 200).fields["type"], TypedUndefined)
