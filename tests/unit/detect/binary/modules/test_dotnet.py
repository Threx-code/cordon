"""The .NET reader (modules.dotnet) against the reference engine's recorded values for the real-file fixtures.
The reader returns plain, schema-shaped data; recode() renders it the way the reference engine reports a
module (bytes as hex, a sequence as the list of its set slots, integers signed) so the two compare leaf by
leaf. The
malformed-file and full-corpus differentials live in the review harness; these fixtures pin the values a
change must not move, and conformance to the declared schema is checked alongside.
"""

from __future__ import annotations

import hashlib
import json
import struct
from typing import Any

import pytest

from cordon_scanner.detect.binary.modules.dotnet import Dotnet, _Method
from cordon_scanner.detect.binary.modules.dotnet_metadata import Tables
from cordon_scanner.detect.binary.modules.layout import Cursor, LazySeq
from cordon_scanner.detect.binary.modules.values import Data, Keyed, Record, Scalar, Seq
from support import ROOT

DIR = ROOT / "tests" / "unit" / "data" / "rule_reference" / "modules"
EXPECTED: dict[str, Any] = json.loads((DIR / "expected.json").read_text(encoding="utf-8"))
DOTNET_FIXTURES = sorted(
    n for n, e in EXPECTED.items() if (e["modules"].get("dotnet") or {}).get("is_dotnet")
)


class Tree:
    """Schema-shaped data rendered and flattened the way the reference engine reports a module, for comparison."""

    @staticmethod
    def recode(declared: Any, data: Any) -> Any:
        if data is None:
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


class TestDotnetValues:
    @pytest.mark.parametrize("name", DOTNET_FIXTURES)
    def test_every_value_is_the_one_the_reference_gives(self, name: str) -> None:
        data = (DIR / name).read_bytes()
        expected = EXPECTED[name]
        assert hashlib.sha256(data).hexdigest() == expected["sha256"]
        want = Tree.leaves(expected["modules"]["dotnet"], "", {})
        got = Tree.leaves(Tree.recode(Dotnet.SCHEMA, Dotnet.data(data)), "", {})
        assert {k: got.get(k, "MISSING") for k in want if got.get(k, "MISSING") != want[k]} == {}
        assert sorted(set(got) - set(want)) == []

    @pytest.mark.parametrize("name", DOTNET_FIXTURES)
    def test_conforms_to_the_declared_schema(self, name: str) -> None:
        data = (DIR / name).read_bytes()
        assert Data.conforms(Dotnet.SCHEMA, Dotnet.data(data)) == []


class TestDotnetBasics:
    def test_not_a_pe_runs_no_module(self) -> None:
        d = Dotnet.data(b"plain text, not an executable at all")
        assert "is_dotnet" not in d  # the module does not load on a non-PE
        assert d["classes"] == {}
        assert d["streams"] == {}

    def test_short_input_does_not_crash(self) -> None:
        assert Dotnet.data(b"MZ" + b"\x00" * 200).get("is_dotnet") in (None, 0)

    def test_classes_are_sparse_and_counted(self) -> None:
        """A class's methods are a sequence read by index; its reported length is the highest set slot."""
        d = Dotnet.data((DIR / "amazon-lambda-core.dll").read_bytes())
        assert d["number_of_classes"] == 8
        klass = d["classes"][0]
        assert Data.length(klass["methods"]) == klass["number_of_methods"]


class Build:
    """Smallest benign inputs that trigger a specific past defect, so a refactor cannot bring it back."""

    @staticmethod
    def pe32plus_dotnet() -> bytes:
        """A minimal 64-bit (PE32+) .NET image: a COM-descriptor directory to a CLI header and a metadata
        root, enough to set is_dotnet. NumberOfRvaAndSizes sits at the PE32+ optional-header offset (108);
        reading it at the PE32 offset (92) would see 0 and reject the file."""
        sec_rva, sec_off = 0x2000, 0x200
        body = bytearray(0x400)
        md = bytearray(struct.pack("<IHHI", 0x424A5342, 1, 1, 0))  # BSJB, major, minor, reserved
        version = b"v4.0.30319\x00\x00"
        md += (
            struct.pack("<I", len(version)) + version + struct.pack("<HH", 0, 0)
        )  # flags, 0 streams
        md_off = 0x100
        body[md_off : md_off + len(md)] = md
        cli = bytearray(72)
        struct.pack_into("<I", cli, 0, 72)  # cb
        struct.pack_into("<II", cli, 8, sec_rva + md_off, len(md))  # metadata RVA + size
        cli_off = 0x40
        body[cli_off : cli_off + 72] = cli
        out = bytearray(0x80)
        out[0:2] = b"MZ"
        struct.pack_into("<I", out, 0x3C, 0x80)  # e_lfanew
        out += b"PE\x00\x00"
        out += struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)  # 64-bit COFF header
        opt = bytearray(0xF0)
        struct.pack_into("<H", opt, 0, 0x20B)  # PE32+ magic
        struct.pack_into("<I", opt, 108, 16)  # NumberOfRvaAndSizes
        struct.pack_into("<II", opt, 112 + 14 * 8, sec_rva + cli_off, 72)  # directory[14] -> CLI
        out += opt
        out += b".text\x00\x00\x00" + struct.pack(
            "<IIIIIIHHI", 0x400, sec_rva, 0x400, sec_off, 0, 0, 0, 0, 0x60000020
        )
        out += bytes(sec_off - len(out)) + body
        return bytes(out)

    @staticmethod
    def tilde_header(typedef_rows: int) -> bytes:
        """A "#~" table-stream header declaring a typedef table of the given row count."""
        return (
            struct.pack("<I", 0)
            + bytes([1, 0, 0, 0])  # major, minor, heap_sizes, reserved
            + struct.pack("<Q", 1 << 0x02)  # only the typedef table is present
            + struct.pack("<Q", 0)  # sorted
            + struct.pack("<I", typedef_rows)
            + bytes(64)
        )


class TestDotnetRegressions:
    def test_a_method_without_a_parameter_list_has_empty_parameters_and_no_count(self) -> None:
        # The identity proof (2026-10-30): on three malformed assemblies whose ParamList the mutation
        # zeroed, the reference reported `parameters` as an empty array and no `number_of_parameters`;
        # ours left `parameters` undefined, which `for all p in m.parameters` tells apart.
        method = _Method((b"Run", 0, [], b"void", [], 0, 0), None, None)  # type: ignore[arg-type]
        assert "parameters" in method and method["parameters"] == {}
        assert "number_of_parameters" not in method

    def test_pe32plus_dotnet_is_recognised(self) -> None:
        """Guard: NumberOfRvaAndSizes is read at the PE32+ offset, so 64-bit assemblies are not dropped."""
        d = Dotnet.data(Build.pe32plus_dotnet())
        assert d["is_dotnet"] == 1
        assert d["number_of_streams"] == 0

    def test_oversized_table_count_aborts_the_walk(self) -> None:
        """Guard: a row count over 10,000 cuts the directory walk short, so classes are not read from it."""
        assert Tables.walk(Cursor(Build.tilde_header(20000)), 0, -1, (0, 0)).completed is False
        assert Tables.walk(Cursor(Build.tilde_header(8)), 0, -1, (0, 0)).completed is True

    def test_lazyseq_defers_decoding(self) -> None:
        """Guard: length, iteration and membership read the keys only; a value is decoded on first access
        and once, and an absent index reads as None without decoding."""
        decoded: list[int] = []
        seq = LazySeq(range(5), lambda i: decoded.append(i) or i * 10)
        assert len(seq) == 5
        assert list(seq) == [0, 1, 2, 3, 4]
        assert Data.length(seq) == 5
        assert 3 in seq and 9 not in seq
        assert decoded == []  # nothing decoded by length/iteration/membership
        assert seq[2] == 20
        assert seq[2] == 20  # cached: still one decode
        assert decoded == [2]
        assert seq.get(99) is None  # absent index: no decode
        assert decoded == [2]
