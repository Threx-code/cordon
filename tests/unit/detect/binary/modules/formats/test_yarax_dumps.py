"""The olecf, msi and vba modules held to YARA-X's own dumps: `yr dump` (yara-x 1.21.0 in the reference
image) over compound files the kit builds to the specification (FormatKit.cfb), recorded once by
scripts/reference/record_module_dumps.py and replayed here leaf by leaf; the fixtures are rebuilt in the
test and their hashes held to the recorded ones. YARA-X leaves a module out of its dump when the file gives
it nothing (no macros, not a compound file); then the module's own flag is held false here."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest
from test_vba_module import SOURCE, Build

from cordon_scanner.detect.binary.modules.formats.msi import Msi
from cordon_scanner.detect.binary.modules.formats.olecf import Olecf
from cordon_scanner.detect.binary.modules.formats.vba import Vba
from cordon_scanner.detect.binary.modules.values import Call, Record, Scalar, Seq
from kits.formatkit import FormatKit
from support import ROOT

RECORDED: dict[str, Any] = json.loads(
    (
        ROOT
        / "tests"
        / "unit"
        / "data"
        / "rule_reference"
        / "yara_tests"
        / "reference-x-1.21.0.json"
    ).read_text(encoding="utf-8")
)
READERS = {
    "olecf": (Olecf.SCHEMA, Olecf.data),
    "msi": (Msi.SCHEMA, Msi.data),
    "vba": (Vba.SCHEMA, Vba.data),
}
FLAGS = {"olecf": "is_olecf", "msi": "is_signed", "vba": "has_macros"}
NAMES = {
    "STORAGE": 1, "STREAM": 2, "ROOT": 5, "UNKNOWN": 0,
    "MODULE_TYPE_STANDARD": 1, "MODULE_TYPE_CLASS": 2, "MODULE_TYPE_UNKNOWN": 3,
}  # fmt: skip
"""YARA-X dumps an enum as its name; a rule reads its number."""


class Fixtures:
    """The files the dumps were taken of, rebuilt here."""

    @staticmethod
    def build() -> dict[str, bytes]:
        code = b"\xcc" * 40 + FormatKit.ovba_literal(
            ('Attribute VB_Name = "Module1"\r\n' + SOURCE).encode("latin-1")
        )
        project = {
            "VBA/dir": Build.dir_stream([(b"Module1", b"Module1", 40, 0x0021)]),
            "VBA/Module1": code,
        }
        return {
            "plain.ole": FormatKit.cfb(
                {"VBA/dir": b"d" * 10, "VBA/Module1": b"m" * 700, "Big": b"B" * 5000}
            ),
            "names.ole": FormatKit.cfb({"\x05Summary": b"s", "Table": b"t" * 3}),
            "project.ole": FormatKit.cfb(project),
            "classmod.ole": FormatKit.cfb(
                {
                    "VBA/dir": Build.dir_stream([(b"Module1", b"Module1", 40, 0x0022)]),
                    "VBA/Module1": code,
                }
            ),
            "unsigned.msi": FormatKit.cfb({"Table": b"t" * 600}),
            "junksig.msi": FormatKit.cfb(
                {"\x05DigitalSignature": b"\x30\x03\x02\x01\x00", "Table": b"t"}
            ),
            "project.docm": FormatKit.ooxml({"word/vbaProject.bin": FormatKit.cfb(project)}),
        }


class Tree:
    @staticmethod
    def ours(schema: Any, data: Any) -> Any:
        if data is None or isinstance(schema, Call):
            return None
        if isinstance(schema, Scalar):
            return data.decode("utf-8", "replace") if isinstance(data, bytes) else data
        if isinstance(schema, Record):
            out = {}
            for k, kind in schema.fields.items():
                if k in data and not isinstance(kind, Call):
                    out[k] = Tree.ours(kind, data[k])
            return out
        if isinstance(schema, Seq):
            return [Tree.ours(schema.item, v) for _, v in sorted(data.items())]
        return data

    @staticmethod
    def theirs(v: Any) -> Any:
        if isinstance(v, str) and v in NAMES:
            return NAMES[v]
        if isinstance(v, dict):
            return {k: Tree.theirs(x) for k, x in v.items()}
        if isinstance(v, list):
            return [Tree.theirs(x) for x in v]
        return v

    @staticmethod
    def leaves(v: Any, prefix: str, out: dict[str, Any]) -> dict[str, Any]:
        if isinstance(v, dict):
            for k, x in v.items():
                Tree.leaves(x, f"{prefix}.{k}", out)
        elif isinstance(v, list):
            for i, x in enumerate(v):
                Tree.leaves(x, f"{prefix}[{i}]", out)
        else:
            out[prefix] = v
        return out


FILES = Fixtures.build()


class TestTheYaraXDumps:
    @pytest.mark.parametrize("name", sorted(FILES))
    def test_the_fixture_is_the_recorded_one(self, name: str) -> None:
        if name.endswith(".docm"):  # the zip wrapper carries the time it was written
            return
        assert hashlib.sha256(FILES[name]).hexdigest() == RECORDED[name]["sha256"]

    @pytest.mark.parametrize("name", sorted(FILES))
    @pytest.mark.parametrize("module", sorted(READERS))
    def test_every_leaf_is_the_one_yara_x_gives(self, name: str, module: str) -> None:
        schema, read = READERS[module]
        data = read(FILES[name])
        recorded = RECORDED[name]["modules"].get(module)
        if recorded is None:  # YARA-X left the module out: the file gives it nothing
            assert data[FLAGS[module]] is False
            return
        want = Tree.leaves(Tree.theirs(recorded), "", {})
        mine = Tree.ours(schema, data)
        for constant in ("StreamType", *(k for k in list(mine) if k.startswith("MODULE_TYPE_"))):
            mine.pop(constant, None)
        got = Tree.leaves(mine, "", {})
        assert {k: got.get(k, "MISSING") for k in want if got.get(k, "MISSING") != want[k]} == {}
        assert sorted(set(got) - set(want)) == []
