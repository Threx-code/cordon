"""The glob index and the Elixir literal blanker on the inputs that reach their rarely used branches (`ecosystems/registry.py`, `packages/hex_literals.py`)."""

from __future__ import annotations

import pytest

from cordon_scanner.ecosystems import registry
from cordon_scanner.ecosystems.packages.hex_literals import ElixirLiterals
from cordon_scanner.ecosystems.registry import EcosystemRegistry


class TestGlobIndex:
    def test_a_double_star_in_the_last_segment_gives_no_name_bounds(self) -> None:
        assert registry._GlobIndex._name_bounds("a/**") == ("", "")
        assert registry._GlobIndex._name_bounds("**/x*y") == ("x", "y")
        assert registry._GlobIndex._name_bounds("**/fixed") == ("fixed", "fixed")

    def test_the_answer_cache_is_cleared_when_it_is_full(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        index = EcosystemRegistry.manifest_index()
        monkeypatch.setattr(registry, "_MAX_ANSWERS", 2)
        index.answers.clear()
        for name in ("a/package.json", "b/package.json", "c/package.json"):
            index.lookup(name)
        assert len(index.answers) <= 2

    def test_a_name_too_short_for_a_patterns_head_and_tail_is_not_a_match(self) -> None:
        index = registry._GlobIndex.build([("first", ("**/ab*bc",))])
        assert index.lookup("abc") is None
        assert index.lookup("abbc") == "first"

    def test_the_install_manifests_of_an_ecosystem_come_from_its_facts(self) -> None:
        assert "package.json" in registry.RegistryFacts.install_manifests("npm")


class TestOwnNames:
    def test_something_that_is_not_an_adapter_in_the_list_is_passed_over(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            EcosystemRegistry, "ECOSYSTEMS", (object(), *EcosystemRegistry.ECOSYSTEMS)
        )
        assert [e.id for e in EcosystemRegistry.own_name_ecosystems("package.json")]


class TestElixirLiterals:
    def test_a_heredoc_that_never_closes_ends_every_later_one_and_code_is_kept(self) -> None:
        text = 'a = """\nnever closed\nend\n'
        assert "end" in ElixirLiterals.blanked(text)

    def test_a_backslash_at_the_end_of_a_line_inside_a_string_stops_the_literal(self) -> None:
        text = 'x = "abc\\\ny = 1\n'
        blanked = ElixirLiterals.blanked(text)
        assert "y = 1" in blanked

    def test_a_literal_cut_off_by_the_end_of_the_text_is_not_closed(self) -> None:
        assert ElixirLiterals.blanked('x = "abc') == 'x = "abc'

    def test_a_backslash_escapes_the_next_character_inside_a_literal(self) -> None:
        assert ElixirLiterals.blanked('x = "a\\"b" y\n') == "x =   y\n"
