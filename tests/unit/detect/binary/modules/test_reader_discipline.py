"""The binary-format readers read bytes only through ``modules.layout`` -- never ``struct`` or ``int.from_bytes``
directly. Those two are how a reader hand-rolls an integer out of bytes; the point of ``modules.layout`` (Cursor,
Layout, Grid, ImageMap) is that a structure is declared once and read in one place, so a reader that reaches
past it is a regression. ``modules.layout`` itself holds the one allowed ``struct``/``int.from_bytes``;
``modules.tlsh`` is a hash transform, not a format reader, so it is out of scope.

Scoped to the format readers by name: modules.pe, modules.elf, modules.dotnet with dotnet_metadata and
dotnet_signatures, modules.signature with x509 and der (the parts those two split into), and
modules.formats' macho and dex. A new reader is added to READERS here.
"""

from __future__ import annotations

import ast
from pathlib import Path

from support import ROOT

READERS = (
    "pe",
    "elf",
    "dotnet",
    "dotnet_metadata",
    "dotnet_signatures",
    "signature",
    "x509",
    "der",
    "formats/macho",
    "formats/dex",
)
BINARY = ROOT / "src" / "cordon_scanner" / "detect" / "binary" / "modules"


class Reads:
    @staticmethod
    def violations(path: Path) -> list[str]:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        out: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                out += [f"{node.lineno}: import {a.name}" for a in node.names if a.name == "struct"]
            elif isinstance(node, ast.ImportFrom) and node.module == "struct":
                out.append(f"{node.lineno}: from struct")
            elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                if node.value.id == "struct":
                    out.append(f"{node.lineno}: struct.{node.attr}")
                elif node.value.id == "int" and node.attr == "from_bytes":
                    out.append(f"{node.lineno}: int.from_bytes")
        return out


class TestReadersUseRuleLayout:
    """No struct / int.from_bytes in a format reader -- every byte read goes through modules.layout."""

    def test_no_struct_or_int_from_bytes_in_the_readers(self) -> None:
        offenders = {
            name: Reads.violations(BINARY / f"{name}.py")
            for name in READERS
            if (BINARY / f"{name}.py").exists()
        }
        assert {k: v for k, v in offenders.items() if v} == {}

    def test_the_check_catches_both_forms(self, tmp_path: Path) -> None:
        sample = tmp_path / "x.py"
        sample.write_text(
            "import struct\n"
            "def f(b):\n"
            "    return struct.unpack('<I', b)[0] + int.from_bytes(b, 'little')\n",
            encoding="utf-8",
        )
        found = Reads.violations(sample)
        assert any("import struct" in v for v in found)
        assert any("struct.unpack" in v for v in found)
        assert any("int.from_bytes" in v for v in found)
