"""Less common statement, declaration and expression forms the parser reads: what each one parses to, or the error it is."""

from __future__ import annotations

import pytest

from cordon_scanner.analysis.javascript.front.parser import Parser
from cordon_scanner.analysis.javascript.front.syntax import Syntax


class _Kit_read:
    @staticmethod
    def read(text: str, *, typescript: bool = False) -> tuple[int, list[str]]:
        parser = Parser(text, typescript=typescript, jsx=not typescript)
        program = parser.program()
        return parser.errors, [n.type for n in Syntax.walk(program)]


read = _Kit_read.read


class TestScript:
    @pytest.mark.parametrize(
        ("text", "node"),
        [
            ("class A { ; x(){} }", "MethodDefinition"),
            ("class A { *g() {} }", "MethodDefinition"),
            ("class A implements B, C { }", "ClassDeclaration"),
            ("with (o) { f(); }", "WithStatement"),
            ("new a['b']();", "NewExpression"),
            ('import("m", { with: { type: "json" } });', "ImportExpression"),
            ('import("m", {},);', "ImportExpression"),
            ("async(x);", "CallExpression"),
            ("async\n(a) => 1;", "ArrowFunctionExpression"),
            ("o = { async m(){}, get x(){ return 1 }, set x(v){} };", "ObjectExpression"),
            ('export { a as "b-c" };', "ExportSpecifier"),
            ('import { "a-b" as c } from "m";', "ImportSpecifier"),
            ("export default class {}", "ExportDefaultDeclaration"),
            ('export { a } from "m" with { type: "json" };', "ExportNamedDeclaration"),
            ("for (var i = 0 in x) {}", "ForInStatement"),
            ("c ? (a) : b;", "ConditionalExpression"),
        ],
    )
    def test_the_form_parses_clean_to_its_node(self, text: str, node: str) -> None:
        errors, types = read(text)
        assert errors == 0
        assert node in types

    @pytest.mark.parametrize("text", ["class { }", "let 1 = 2;", "x as y;"])
    def test_a_form_that_is_not_script_is_one_error(self, text: str) -> None:
        errors, types = read(text)
        assert errors == 1
        assert types == ["Program", "Error"]

    def test_a_newline_before_as_ends_the_expression(self) -> None:
        errors, types = read("x\nas y;")
        assert errors == 1
        assert types[:3] == ["Program", "ExpressionStatement", "Identifier"]


class TestTypeScriptForms:
    @pytest.mark.parametrize(
        ("text", "node"),
        [
            ("class A { [key: string]: number; m(){} }", "TSDeclaration"),
            ("class A { [k]() {} }", "MethodDefinition"),
            ("x as const;", "TSAsExpression"),
            ("const f = (a?, b?) => 1;", "ArrowFunctionExpression"),
            ("import type x from 'm';", "ImportDefaultSpecifier"),
            ("import type = x;\nfoo();", "TSImportEquals"),
            ("import { type a, type as b, type } from 'm';", "ImportSpecifier"),
            ("export default abstract class {}", "ClassDeclaration"),
            ("export = x;", "TSExportAssignment"),
            ("export type { A };", "ExportSpecifier"),
            ("export { type A };", "ExportSpecifier"),
        ],
    )
    def test_the_form_parses_clean_to_its_node(self, text: str, node: str) -> None:
        errors, types = read(text, typescript=True)
        assert errors == 0
        assert node in types
