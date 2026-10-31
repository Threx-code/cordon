"""The certificate paths on two real signed files, held to both references: GitHub CLI 2.102.0's
Windows installer (a version 4 compound file with an Authenticode signature, its metadata signed too, and
a Microsoft timestamp) and its notarised macOS arm64 binary (a code signature with three certificates).
The files are too large to keep here; their dumps by `yara -D` (YARA 4.5.8) and `yr dump` (YARA-X
1.21.0) are recorded with their SHA-256 in tests/unit/data/rule_reference/signed, and the files are read
from the directory CORDON_SIGNED_FIXTURES names (the Docker volume cordon-signed-fixtures, mounted read
only). Without it these tests are skipped, and say why.

One named divergence from YARA-X, on the installer: its file digest is not the signed content (see
modules.formats.msi), so YARA-X's `file_digest` differs from the signed `digest` and its `verified` is
false; ours equals the signed digest and is verified. Ours also keeps `length_of_chain` beside `chain`."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest
from test_yara_dumps import Tree as YaraTree
from test_yarax_dumps import Tree as YaraXTree

from cordon_scanner.detect.binary.modules.formats.macho import Macho
from cordon_scanner.detect.binary.modules.formats.macho_tables import MachoTables
from cordon_scanner.detect.binary.modules.formats.msi import Msi
from cordon_scanner.detect.binary.modules.formats.olecf import Olecf
from support import ROOT

DIR = ROOT / "tests" / "unit" / "data" / "rule_reference" / "signed"
YARA: dict[str, Any] = json.loads((DIR / "reference-4.5.8.json").read_text(encoding="utf-8"))
YARA_X: dict[str, Any] = json.loads((DIR / "reference-x-1.21.0.json").read_text(encoding="utf-8"))
READERS = {
    "macho": (Macho.SCHEMA, Macho.data),
    "msi": (Msi.SCHEMA, Msi.data),
    "olecf": (Olecf.SCHEMA, Olecf.data),
}


class Fixture:
    @staticmethod
    def read(name: str) -> bytes:
        """The file, held to its recorded SHA-256; the test is skipped, with the reason, without it."""
        root = os.environ.get("CORDON_SIGNED_FIXTURES")
        if not root:
            pytest.skip(
                "CORDON_SIGNED_FIXTURES is not set: the signed files live in a Docker volume"
            )
        path = Path(root) / name
        if not path.is_file():
            pytest.skip(f"{name} is not in {root}")
        data = path.read_bytes()
        assert hashlib.sha256(data).hexdigest() == YARA_X[name]["sha256"]
        return data

    @staticmethod
    def differences(want: dict[str, Any], got: dict[str, Any]) -> dict[str, Any]:
        return {k: got.get(k, "MISSING") for k in want if got.get(k, "MISSING") != want[k]}


class TestTheYaraXDumps:
    @pytest.mark.parametrize(
        ("name", "module"),
        [(n, m) for n in sorted(YARA_X) for m in sorted(YARA_X[n]["modules"]) if m in READERS],
    )
    def test_every_leaf_is_the_one_yara_x_gives(self, name: str, module: str) -> None:
        data = Fixture.read(name)
        schema, read = READERS[module]
        want = YaraXTree.leaves(YaraXTree.theirs(YARA_X[name]["modules"][module]), "", {})
        mine = YaraXTree.ours(schema, read(data))
        for constant in (*MachoTables.MACHO, "StreamType"):
            mine.pop(constant, None)
        got = {k: v for k, v in YaraXTree.leaves(mine, "", {}).items() if not k.endswith(".fsize")}
        diverged = (
            {k for k in want if k.endswith((".file_digest", ".verified"))}
            if module == "msi"
            else set()
        )
        assert Fixture.differences({k: v for k, v in want.items() if k not in diverged}, got) == {}
        assert sorted(k for k in set(got) - set(want) if not k.endswith(".length_of_chain")) == []

    def test_the_installer_digest_is_the_signed_one(self) -> None:
        name = "gh_2.102.0_windows_386.msi"
        theirs = YARA_X[name]["modules"]["msi"]["signatures"][0]
        ours = Msi.data(Fixture.read(name))["signatures"][0]
        assert theirs["file_digest"] != theirs["digest"] and theirs["verified"] is False
        assert ours["file_digest"] == ours["digest"] == theirs["digest"].encode()
        assert ours["verified"] == 1
        assert ours["countersignatures"][0]["verified"] == 1


class TestTheYaraDumps:
    def test_every_leaf_is_the_one_yara_gives(self) -> None:
        name = "gh-macos-arm64"
        data = Fixture.read(name)
        want = YaraTree.leaves(YARA[name]["modules"]["macho"], "", {})
        got = YaraTree.ours("macho", data)
        assert Fixture.differences(want, got) == {}
        assert sorted(set(got) - set(want)) == []
