"""The Nix lexer and attribute-set reader on the shapes a real flake or lock writes less often (`ecosystems/packages/nix.py`)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from cordon_scanner.ecosystems.packages.nix import Fetchers, NixError, NixLexer, NixReader
from cordon_scanner.ecosystems.registry import EcosystemRegistry
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import Limits


class _Kit:
    @staticmethod
    def read(text: str) -> Any:
        return NixReader(NixLexer.tokens(text)).value(0)


class TestLexer:
    def test_a_closing_bracket_with_nothing_open_is_refused(self) -> None:
        with pytest.raises(NixError, match="closing bracket with nothing open"):
            NixLexer.balanced(NixLexer.tokens("}"))

    def test_a_bracket_that_never_closes_is_refused(self) -> None:
        with pytest.raises(NixError, match="does not close"):
            _Kit.read("[")

    def test_a_comment_that_never_ends_is_refused(self) -> None:
        with pytest.raises(NixError, match="unterminated comment"):
            NixLexer.tokens("/* open")

    def test_a_letter_or_digit_the_grammar_does_not_allow_is_refused(self) -> None:
        with pytest.raises(NixError, match="unreadable identifier"):
            NixLexer.tokens("é")
        with pytest.raises(NixError, match="unreadable number"):
            NixLexer.tokens("²")

    def test_more_tokens_than_the_limit_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(NixLexer, "MAX_TOKENS", 3)
        with pytest.raises(NixError, match="more tokens than an expression holds"):
            NixLexer.tokens("a b c d e")

    def test_strings_keep_their_escapes_and_interpolations_are_skipped_whole(self) -> None:
        assert _Kit.read('{ a = "q\\"r"; }') == {"a": 'q"r'}
        assert _Kit.read("{ a = ''x\\ny''; }") == {"a": "x\\ny"}
        assert _Kit.read('{ a = "x${ {b = 1;}.b }y"; }') == {"a": None}
        assert _Kit.read("{ a = ''x ${y} ''; }") == {"a": None}

    def test_strings_that_never_end_are_refused(self) -> None:
        with pytest.raises(NixError, match="unterminated string"):
            NixLexer.tokens('{ a = "x${ unclosed"; }')
        with pytest.raises(NixError, match="unterminated indented string"):
            NixLexer.tokens("{ a = ''never; }")

    def test_an_interpolation_that_never_closes_is_refused(self) -> None:
        with pytest.raises(NixError, match="interpolation that does not close"):
            NixLexer.tokens('"${ x')


class TestReader:
    def test_an_empty_file_ends_inside_a_value(self) -> None:
        with pytest.raises(NixError, match="file ends inside a value"):
            _Kit.read("")

    def test_nesting_past_the_limit_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(NixReader, "MAX_DEPTH", 2)
        with pytest.raises(NixError, match="nested too deeply"):
            _Kit.read("{ a = { b = { c = { d = 1; }; }; }; }")

    def test_a_function_pattern_is_not_an_attribute_set(self) -> None:
        assert _Kit.read("{ a = {x, y}: 1; }") == {"a": None}

    def test_inherit_and_a_second_definition_are_handled_not_guessed(self) -> None:
        assert _Kit.read("{ inherit foo; a = 1; }") == {"a": None}
        assert _Kit.read("{ a.b = 1; a.c = 2; }") == {"a": {"b": None, "c": None}}
        assert _Kit.read("{ a = {b = 1;}; a = {c = 2;}; }") == {"a": {"b": None, "c": None}}

    def test_an_attribute_without_a_name_and_a_value_is_refused(self) -> None:
        with pytest.raises(NixError, match="not `name = value;`"):
            _Kit.read("{ 1 }")

    def test_a_set_that_never_closes_is_refused(self) -> None:
        with pytest.raises(NixError):
            _Kit.read("{ a = 1;")


class _Files:
    @staticmethod
    def fc(path: str, text: str) -> FileContent:
        return FileContent.from_bytes(path, text.encode("utf-8"), Limits())

    @staticmethod
    def adapter() -> Any:
        return EcosystemRegistry.BY_ID["nix"]


class TestFlake:
    def parse(self, text: str):
        return _Files.adapter().parse_manifest(_Files.fc("flake.nix", text))

    def test_a_flake_that_is_not_an_attribute_set_is_refused(self) -> None:
        assert "a flake that is not an attribute set" in self.parse("[ ]").parse_error

    def test_a_flake_with_neither_inputs_nor_outputs_is_refused(self) -> None:
        assert "neither inputs nor outputs" in self.parse('{ description = "x"; }').parse_error

    def test_an_input_written_as_a_bare_string_is_that_inputs_url(self) -> None:
        manifest = self.parse(
            '{ inputs = { nixpkgs = "github:NixOS/nixpkgs/nixos-24.05"; }; outputs = _: {}; }'
        )
        assert [d.field_name for d in manifest.dependencies] == ["inputs.nixpkgs"]
        assert manifest.dependencies[0].name == "nixos/nixpkgs"

    def test_an_input_that_follows_another_declares_nothing_and_says_so(self) -> None:
        manifest = self.parse(
            '{ inputs = { a.follows = "b"; b.url = "github:o/b"; }; outputs = _: {}; }'
        )
        assert [d.field_name for d in manifest.dependencies] == ["inputs.b"]
        assert "input a follows b" in manifest.sources


NAR = "sha256-" + "A" * 43 + "="


class TestFlakeLock:
    def lock(self, nodes: dict[str, Any], root_inputs: dict[str, Any]) -> Any:
        text = json.dumps(
            {"root": "root", "version": 7, "nodes": {"root": {"inputs": root_inputs}, **nodes}}
        )
        return _Files.adapter().parse_lockfile(_Files.fc("flake.lock", text))

    def test_text_that_is_not_json_is_refused(self) -> None:
        graph = _Files.adapter().parse_lockfile(_Files.fc("flake.lock", "{nope"))
        assert graph.parse_error.startswith("invalid JSON")

    def test_a_follows_path_is_walked_from_the_root_to_the_node_it_names(self) -> None:
        nixpkgs = {
            "locked": {
                "type": "github",
                "owner": "NixOS",
                "repo": "nixpkgs",
                "rev": "abc",
                "narHash": NAR,
            },
            "original": {"type": "indirect", "id": "nixpkgs"},
        }
        graph = self.lock(
            {"nixpkgs": nixpkgs},
            {"nixpkgs": "nixpkgs", "utils": ["nixpkgs"], "ghost": ["missing"]},
        )
        [entry] = graph.entries
        assert entry.resolved_from == "git+https://github.com/NixOS/nixpkgs#abc"
        assert entry.direct is True
        assert "indirect flake:nixpkgs" in entry.platform
        assert entry.integrity == NAR


class TestFetchers:
    def test_a_fetcher_with_nothing_after_it_is_skipped_and_a_broken_argument_set_is_skipped(
        self,
    ) -> None:
        tokens = NixLexer.tokens('{ a = fetchurl { url = "x"; ')  # never closes
        assert list(Fetchers.calls(tokens)) == []
        assert list(Fetchers.calls(NixLexer.tokens("fetchurl"))) == []

    @pytest.mark.parametrize(
        ("value", "typed"),
        [
            ("A" * 43 + "=", "sha256-" + "A" * 43 + "="),
            ("A" * 86 + "==", "sha512-" + "A" * 86 + "=="),
            ("a" * 128, "sha512:" + "a" * 128),
            ("sha256-abc", "sha256-abc"),
            (None, None),
        ],
    )
    def test_a_hash_is_given_in_one_typed_form_whichever_way_it_was_written(
        self, value: str | None, typed: str | None
    ) -> None:
        assert Fetchers.sri(value) == typed


class TestMoreNix:
    def test_a_closed_comment_is_stepped_over(self) -> None:
        assert _Kit.read("{ a = 1; /* note */ b = 2; }") == {"a": None, "b": None}

    def test_an_opening_brace_that_never_closes_is_refused(self) -> None:
        with pytest.raises(NixError):
            _Kit.read("{")

    def test_an_input_with_no_url_is_looked_up_by_its_own_name(self) -> None:
        manifest = _Files.adapter().parse_manifest(
            _Files.fc("flake.nix", "{ inputs = { nixpkgs = {}; }; outputs = _: {}; }")
        )
        assert [d.field_name for d in manifest.dependencies] == ["inputs.nixpkgs"]

    @pytest.mark.parametrize(
        ("value", "typed"),
        [
            ("0123456789abcdfghijklmnpqrsvwxyz", "sha1:0123456789abcdfghijklmnpqrsvwxyz"),
            ("odd", "sha256:odd"),
        ],
    )
    def test_a_bare_digest_of_a_known_length_is_typed_and_any_other_is_taken_as_sha256(
        self, value: str, typed: str
    ) -> None:
        assert Fetchers.sri(value) == typed

    def test_a_lock_without_nodes_and_a_node_without_its_locked_revision_are_refused(self) -> None:
        adapter = _Files.adapter()
        no_nodes = adapter.parse_lockfile(_Files.fc("flake.lock", '{"root": "root"}'))
        assert "without its nodes and root" in no_nodes.parse_error
        text = '{"root": "root", "nodes": {"root": {"inputs": {}}, "x": {"original": {}}}}'
        unlocked = adapter.parse_lockfile(_Files.fc("flake.lock", text))
        assert "without its locked revision" in unlocked.parse_error

    def test_a_path_input_is_named_by_its_last_directory(self) -> None:
        text = json.dumps(
            {
                "root": "root",
                "nodes": {
                    "root": {"inputs": {"local": "local"}},
                    "local": {"locked": {"type": "path", "path": "/home/me/proj/"}},
                },
            }
        )
        graph = _Files.adapter().parse_lockfile(_Files.fc("flake.lock", text))
        assert [(e.name, e.local) for e in graph.entries] == [("proj", True)]
