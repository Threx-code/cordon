"""JSX and TypeScript forms the parser reads past: fragments, interfaces, ambient declarations, type syntax."""

from __future__ import annotations

import pytest

from cordon_scanner.analysis.javascript.front.parser import Parser
from cordon_scanner.analysis.javascript.front.syntax import Syntax


class Read:
    @staticmethod
    def of(
        text: str, *, typescript: bool = False, jsx: bool | None = None
    ) -> tuple[int, list[str]]:
        parser = Parser(text, typescript=typescript, jsx=(not typescript) if jsx is None else jsx)
        program = parser.program()
        return parser.errors, [n.type for n in Syntax.walk(program)]


class TestJsx:
    def test_a_fragment_holds_its_expressions(self) -> None:
        errors, types = Read.of("<>hi {x}</>;")
        assert errors == 0
        assert "JSXFragment" in types and "Identifier" in types

    def test_elements_nest_with_text_and_expressions(self) -> None:
        errors, types = Read.of("<a><b/> text <c>{d}</c></a>;")
        assert errors == 0
        assert types.count("JSXElement") == 3

    def test_an_element_that_is_never_closed_is_an_error(self) -> None:
        errors, types = Read.of("<a><b>")
        assert errors == 1
        assert types == ["Program", "Error"]

    def test_an_element_as_an_attribute_value(self) -> None:
        errors, types = Read.of('<A b=<C d="1" /> />;')
        assert "JSXElement" in types or errors == 1

    def test_type_arguments_on_an_element_in_a_typescript_file(self) -> None:
        errors, types = Read.of('<A<string> b="1" />;', typescript=True, jsx=True)
        assert "JSXElement" in types or errors == 1


class TestTypeScriptDeclarations:
    def test_an_interface_with_parents_is_skipped_and_what_follows_is_read(self) -> None:
        errors, types = Read.of("interface A<T> extends B, C { x: T }\nfoo();", typescript=True)
        assert errors == 0
        assert types == [
            "Program",
            "TSDeclaration",
            "ExpressionStatement",
            "CallExpression",
            "Identifier",
        ]

    def test_a_type_alias_is_skipped(self) -> None:
        errors, types = Read.of("type x = 1;\nfoo();", typescript=True)
        assert errors == 0
        assert "TSDeclaration" in types and "CallExpression" in types

    def test_a_type_followed_by_a_name_but_no_equals_is_two_expressions(self) -> None:
        errors, types = Read.of("type\nx;", typescript=True)
        assert errors == 0
        assert types.count("ExpressionStatement") == 2

    def test_a_type_word_with_no_equals_is_no_alias_and_the_next_statement_is_read(self) -> None:
        errors, types = Read.of("type x\nfoo();", typescript=True)
        assert errors == 1
        assert "TSDeclaration" not in types and "CallExpression" in types

    @pytest.mark.parametrize(
        "text",
        ['declare module "m";', "declare namespace A.B.C { }", "declare module Foo.Bar { }"],
    )
    def test_an_ambient_module_or_namespace_is_one_declaration(self, text: str) -> None:
        errors, types = Read.of(text, typescript=True)
        assert errors == 0
        assert types == ["Program", "TSDeclaration"]


class TestTypeSyntax:
    @pytest.mark.parametrize(
        "text",
        [
            "let f: (a: number) => void = g;",
            "function f(a:) {}",
            "let m: Map<string, Array<number>> = x;",
            "let m: A<B<C<number>>> = x;",
            "let o: A | { x: number } = y;",
            "const c = (a: number): ((b: string) => void) => g;",
        ],
    )
    def test_a_type_is_read_past_whatever_its_shape(self, text: str) -> None:
        errors, types = Read.of(text + "\nrun();", typescript=True)
        assert errors == 0
        assert "CallExpression" in types

    def test_type_arguments_closed_with_a_double_angle(self) -> None:
        errors, types = Read.of("f<A<B>>(x);", typescript=True)
        assert errors == 0
        assert types[:3] == ["Program", "ExpressionStatement", "CallExpression"]

    def test_type_arguments_closed_with_a_triple_angle(self) -> None:
        errors, types = Read.of("f<A<B<C>>>(x);", typescript=True)
        assert errors == 0
        assert types[:3] == ["Program", "ExpressionStatement", "CallExpression"]

    def test_a_less_than_past_the_lookahead_is_a_comparison(self) -> None:
        errors, types = Read.of("x = a < " + " + ".join(["1"] * 400) + ";", typescript=True)
        assert errors == 0
        assert "BinaryExpression" in types
