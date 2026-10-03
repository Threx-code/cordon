"""G4: Perl, Lua, Dart, Elixir and R are recognised and carry their own capability primitives, so the
behavioural composites apply to them as they do to Python and JavaScript."""

from __future__ import annotations

from pathlib import Path

import pytest

from cordon_scanner.core.comments import LINE_COMMENT_OPENERS
from cordon_scanner.langs.registry import LanguageRegistry
from cordon_scanner.rules.loader import RuleLoader

PACK = (
    Path(__file__).resolve().parents[2]
    / "src/cordon_scanner/rules/builtin/capabilities-perl-lua-dart-elixir-r.yaml"
)


class TestRecognition:
    @pytest.mark.parametrize(
        "path, language",
        [
            ("lib/Foo/Bar.pm", "perl"),
            ("Makefile.PL", "perl"),
            ("script.pl", "perl"),
            ("R/install.R", "r"),
            ("analysis.r", "r"),
            ("init.lua", "lua"),
            ("lib/app.ex", "elixir"),
            ("mix.exs", "elixir"),
            ("lib/main.dart", "dart"),
        ],
    )
    def test_extensions(self, path, language):
        assert LanguageRegistry.identify_language(path) == language

    def test_a_suffix_that_merely_starts_the_same_is_not_r(self):
        assert LanguageRegistry.identify_language("main.rs") == "rust"
        assert LanguageRegistry.identify_language("Gemfile.rb") == "ruby"

    def test_interpreters(self):
        for interpreter, language in (
            ("Rscript", "r"),
            ("elixir", "elixir"),
            ("luajit", "lua"),
            ("perl", "perl"),
        ):
            assert LanguageRegistry.INTERPRETERS[interpreter] == language

    def test_comments_are_not_read_as_code(self):
        assert LINE_COMMENT_OPENERS["perl"] == ("#",) and LINE_COMMENT_OPENERS["r"] == ("#",)


class TestThePack:
    @pytest.fixture
    def rules(self):
        return [compiled.rule for compiled in RuleLoader(require_tests=True).load_file(PACK)]

    def test_every_language_has_the_primitives_the_composites_need(self, rules):
        by_language: dict[str, set[str]] = {}
        for rule in rules:
            for language in rule.languages:
                by_language.setdefault(language, set()).add(rule.capability.value)
        needed = {
            "decode",
            "decompress",
            "execute",
            "spawn",
            "persist",
            "fetch_exec",
            "egress",
            "deserialize",
        }
        for language in ("perl", "lua", "elixir", "r"):
            assert needed <= by_language[language], (language, needed - by_language[language])
        # Dart: no string evaluator and no object deserialiser, so neither is claimed beyond
        # loading code from a URI.
        assert needed - {"deserialize"} <= by_language["dart"]
        assert "deserialize" not in by_language["dart"]

    def test_every_rule_is_informational_signal_only(self, rules):
        assert {r.severity.name for r in rules} == {"INFO"}
        assert len({r.id for r in rules}) == len(rules)
