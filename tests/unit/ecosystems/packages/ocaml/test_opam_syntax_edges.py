"""The opam file reader's refusals and rarer constructs: comments, triple-quoted strings,
sections, and text that is cut short or nested past the limit."""

from __future__ import annotations

import pytest

from cordon_scanner.ecosystems.packages.ocaml.opam_syntax import (
    Formula,
    Node,
    OpamDocument,
    OpamError,
    OpamLexer,
    OpamParser,
)
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.limits import Limits


class _Kit:
    @staticmethod
    def load(text: str) -> OpamDocument:
        return OpamDocument.load(FileContent.from_bytes("a.opam", text.encode("utf-8"), Limits()))


load = _Kit.load


class TestLexer:
    def test_comments_and_a_triple_quoted_string_are_read_through(self) -> None:
        tokens = OpamLexer.tokens('# line\n(* block *) a: """x "quoted" y""" b: "p\\"q"\n')
        assert ("str", 'x "quoted" y') in tokens
        assert ("str", 'p"q') in tokens
        assert [t for t in tokens if t[0] == "ident"] == [("ident", "a"), ("ident", "b")]

    @pytest.mark.parametrize(
        ("text", "reason"),
        [
            ("(* never ends", "unterminated comment"),
            ('a: """never', "unterminated string"),
            ('a: "never', "unterminated string"),
            ("a: \x01", "not part of the opam format"),
        ],
    )
    def test_text_the_lexer_cannot_close_is_refused(self, text: str, reason: str) -> None:
        with pytest.raises(OpamError, match=reason):
            OpamLexer.tokens(text)

    def test_more_tokens_than_the_limit_are_refused(self) -> None:
        with pytest.raises(OpamError, match="more tokens"):
            OpamLexer.tokens("a " * (OpamLexer.MAX_TOKENS + 1))


class TestParser:
    @pytest.mark.parametrize(
        ("text", "reason"),
        [
            ("a:", "ends inside a value"),
            ('"x"', "does not start with its name"),
            ("a: [ b", "does not close"),
            ("a: &", "starts with an operator"),
            ("s { a: b", "ends inside a value"),
            ("s x", "does not close"),
            ("a: b {", "does not close"),
        ],
    )
    def test_a_file_cut_short_or_malformed_is_refused(self, text: str, reason: str) -> None:
        with pytest.raises(OpamError, match=reason):
            load(text)

    def test_sections_nested_past_the_limit_are_refused(self) -> None:
        depth = OpamParser.MAX_DEPTH + 2
        with pytest.raises(OpamError, match="nested too deeply"):
            load("s { " * depth + "a: b " + "} " * depth)

    def test_a_value_nested_past_the_limit_is_refused(self) -> None:
        depth = OpamParser.MAX_DEPTH + 2
        with pytest.raises(OpamError, match="nested too deeply"):
            load("a: " + "(" * depth + "b" + ")" * depth)

    def test_a_named_section_is_kept_with_its_fields(self) -> None:
        document = load('url {\n  src: "https://h.example/a.tgz"\n}\nextra-source "f" { x: "y" }\n')
        section = document.fields["section:url"][0]
        assert section.kind == "section"
        assert [f.text for f in section.items] == ["src"]
        assert "section:extra-source" in document.fields

    def test_a_negation_binds_to_the_value_after_it(self) -> None:
        node = load("a: !b").fields["a"][0]
        assert (node.kind, node.text) == ("unop", "!")
        assert Formula.render(node) == "!b"


class TestRender:
    def test_each_shape_of_a_formula_is_written_back(self) -> None:
        document = load('depends: [ "a" {>= "1" & < "2"} (b | !c) ]')
        rendered = Formula.render(document.fields["depends"][0])
        assert rendered.startswith('["a"')
        assert "(b | !c)" in rendered

    def test_a_section_node_renders_as_nothing(self) -> None:
        assert Formula.render(Node("section", "url")) == ""
