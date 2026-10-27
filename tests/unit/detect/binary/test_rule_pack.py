"""The built-in rule pack (`--rule-file builtin`) and the `path_include` a rule states."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from cordon_scanner.detect.binary.rule_files import BUILTIN_PACK, RuleFileEngine

PACK_DIRECTORY = BUILTIN_PACK.parent


class TestThePackShipped:
    def test_it_is_the_upstream_rules_at_a_pinned_commit_with_their_licence(self) -> None:
        manifest = json.loads((PACK_DIRECTORY / "MANIFEST.json").read_text(encoding="utf-8"))
        assert manifest["licence"] == "Apache-2.0" and len(manifest["commit"]) == 40
        assert (
            (PACK_DIRECTORY / "upstream" / "LICENSE")
            .read_text(encoding="utf-8")
            .startswith(("Apache License", "\n", " "))
        )
        text = BUILTIN_PACK.read_text(encoding="utf-8")
        assert manifest["commit"] in text and "Apache License 2.0" in text
        # Every kept rule is in the pack unchanged; nothing dropped is.
        for name in manifest["kept"]:
            assert (PACK_DIRECTORY / "upstream" / name).read_text(encoding="utf-8") in text
        for name in manifest["dropped"]:
            assert (PACK_DIRECTORY / "upstream" / name).read_text(encoding="utf-8") not in text

    def test_builtin_names_the_shipped_pack_and_it_compiles(self) -> None:
        from cordon_scanner.detect.binary.rule_lang import Rules

        engine = RuleFileEngine("builtin")
        assert engine.version and isinstance(engine.rules, Rules)
        assert len(engine.rules.rules) == 40


class TestPathInclude:
    @staticmethod
    def match(path_include: str | None) -> SimpleNamespace:
        return SimpleNamespace(
            rule="r", meta={"path_include": path_include} if path_include is not None else {}
        )

    @pytest.mark.parametrize(
        ("path", "applies"),
        [
            ("pkg/setup.py", True),
            ("package.tgz!package/index.JS", True),
            ("README.md", False),
            ("docs/notes.txt", False),
        ],
    )
    def test_a_rule_counts_only_for_the_files_it_names(self, path, applies) -> None:
        assert RuleFileEngine.applies(self.match("*.py,*.js"), path) is applies

    def test_a_rule_that_names_none_counts_everywhere(self) -> None:
        assert RuleFileEngine.applies(self.match(None), "anything.bin")
        assert RuleFileEngine.applies(self.match(""), "anything.bin")

    def test_the_shipped_pack_exists(self) -> None:
        assert Path(BUILTIN_PACK).is_file()
