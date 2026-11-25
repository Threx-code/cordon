"""Facts version 6: the record counts each file's size class and the encoded literals of the text files, how many agent instruction files there are and how many tools a package declares, and keeps no text.

Each field is present and counted on a fixture that has the thing, and is zero on one that does not. The record says how many literals of each kind there were, never what they said.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.files.file_facts import FileFacts
from cordon_scanner.report.facts import ScanFacts

MANIFEST = json.dumps({"name": "p", "version": "1.0.0", "main": "index.js"})
SECRET_B64 = base64.b64encode(
    b"a payload that must never be written into a facts record, " * 3
).decode()


class Package:
    @staticmethod
    def facts(root: Path) -> dict[str, Any]:
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(root)
        return ScanFacts.of(result)["package"]

    @staticmethod
    def plain(root: Path) -> Path:
        (root / "package.json").write_text(MANIFEST, encoding="utf-8")
        (root / "index.js").write_text("module.exports = 1;\n", encoding="utf-8")
        return root


class TestSizeClasses:
    @pytest.mark.parametrize(
        ("size", "name"),
        [
            (0, "empty"),
            (1, "tiny"),
            (1023, "tiny"),
            (1024, "small"),
            (16 * 1024 - 1, "small"),
            (16 * 1024, "medium"),
            (256 * 1024, "large"),
            (4 * 1024 * 1024 - 1, "large"),
            (4 * 1024 * 1024, "huge"),
        ],
    )
    def test_each_boundary_belongs_to_one_class(self, size: int, name: str) -> None:
        assert FileFacts.size_class(size) == name

    def test_every_class_is_in_the_record_and_each_file_is_counted_once(
        self, tmp_path: Path
    ) -> None:
        root = Package.plain(tmp_path)
        (root / "big.txt").write_text("x" * 20_000, encoding="utf-8")
        classes = Package.facts(root)["size_classes"]
        assert set(classes) == {"empty", "tiny", "small", "medium", "large", "huge"}
        assert classes["tiny"] >= 2 and classes["medium"] == 1 and classes["huge"] == 0
        assert sum(classes.values()) == Package.facts(root)["files_scanned"]


class TestEncodedLiterals:
    def test_a_package_with_none_has_every_kind_at_zero(self, tmp_path: Path) -> None:
        assert Package.facts(Package.plain(tmp_path))["encoded_literals"] == {
            "base64": 0,
            "hex": 0,
            "hex_escape": 0,
            "unicode_escape": 0,
        }

    def test_each_kind_is_counted_on_a_fixture_that_has_it(self, tmp_path: Path) -> None:
        root = Package.plain(tmp_path)
        hexa, escapes, units = "ab12" * 20, "\\x41" * 20, "\\u0041" * 10
        lines = [
            f'var a = "{SECRET_B64}";',
            f'var b = "{hexa}";',
            f'var c = "{escapes}";',
            f'var d = "{units}";',
        ]
        (root / "blobs.js").write_text("\n".join(lines) + "\n", encoding="utf-8")
        found = Package.facts(root)["encoded_literals"]
        assert found == {"base64": 1, "hex": 1, "hex_escape": 1, "unicode_escape": 1}

    def test_the_count_is_of_literals_and_two_of_one_kind_are_two(self, tmp_path: Path) -> None:
        root = Package.plain(tmp_path)
        (root / "two.js").write_text(
            f'x("{SECRET_B64}");\ny("{SECRET_B64[::-1]}");\n', encoding="utf-8"
        )
        assert Package.facts(root)["encoded_literals"]["base64"] == 2

    def test_prose_and_short_strings_are_not_literals(self, tmp_path: Path) -> None:
        root = Package.plain(tmp_path)
        (root / "prose.md").write_text(
            "The quick brown fox jumps over the lazy dog. " * 30 + "abc123 deadbeef\n",
            encoding="utf-8",
        )
        assert sum(Package.facts(root)["encoded_literals"].values()) == 0

    def test_no_text_of_a_literal_reaches_the_record(self, tmp_path: Path) -> None:
        root = Package.plain(tmp_path)
        (root / "blob.js").write_text(f'var a = "{SECRET_B64}";\n', encoding="utf-8")
        result = Scanner(Config.default().with_overrides(use_cache=False)).scan(root)
        text = json.dumps(ScanFacts.of(result))
        assert SECRET_B64 not in text and SECRET_B64[:24] not in text

    def test_a_binary_file_is_not_read_for_them(self, tmp_path: Path) -> None:
        root = Package.plain(tmp_path)
        (root / "blob.bin").write_bytes(b"\x00\x01" + SECRET_B64.encode() + b"\x00")
        assert Package.facts(root)["encoded_literals"]["base64"] == 0

    def test_only_the_first_window_is_read(self) -> None:
        assert FileFacts.encoded_literals(b" " * FileFacts.WINDOW + SECRET_B64.encode()) == {}


class TestInstructionFiles:
    def test_none_is_zero(self, tmp_path: Path) -> None:
        assert Package.facts(Package.plain(tmp_path))["instruction_files"] == 0

    def test_each_instruction_file_is_counted(self, tmp_path: Path) -> None:
        root = Package.plain(tmp_path)
        (root / "CLAUDE.md").write_text("Be careful.\n", encoding="utf-8")
        (root / "AGENTS.md").write_text("Run the tests.\n", encoding="utf-8")
        (root / "skills" / "deploy").mkdir(parents=True)
        (root / "skills" / "deploy" / "SKILL.md").write_text(
            "---\nname: deploy\n---\nDeploy.\n", encoding="utf-8"
        )
        (root / "README.md").write_text("Not an instruction file.\n", encoding="utf-8")
        assert Package.facts(root)["instruction_files"] == 3

    @pytest.mark.parametrize(
        ("path", "yes"),
        [
            ("CLAUDE.md", True),
            ("a/b/AGENTS.md", True),
            (".cursorrules", True),
            (".github/copilot-instructions.md", True),
            ("README.md", False),
            ("docs/CLAUDE.txt", False),
        ],
    )
    def test_which_paths_are_instruction_files(self, path: str, yes: bool) -> None:
        assert FileFacts.is_instruction(path) is yes


class TestDeclaredTools:
    def test_a_package_that_declares_no_tool_list_has_zero(self, tmp_path: Path) -> None:
        assert Package.facts(Package.plain(tmp_path))["mcp_tools"] == 0

    def test_a_package_that_declares_its_tools_as_data_counts_them(self, tmp_path: Path) -> None:
        root = Package.plain(tmp_path)
        tools = {
            "tools": [
                {"name": "read", "description": "Read a file", "inputSchema": {"type": "object"}},
                {"name": "write", "description": "Write a file", "inputSchema": {"type": "object"}},
            ]
        }
        (root / "tools.json").write_text(json.dumps(tools), encoding="utf-8")
        assert Package.facts(root)["mcp_tools"] == 2
