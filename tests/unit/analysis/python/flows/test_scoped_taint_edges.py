"""The scoped taint helpers on the node shapes and call forms that reach their early exits (`analysis/python/scoped_taint.py`)."""

from __future__ import annotations

import ast

from cordon_scanner.analysis.python.scoped_taint import BindingForms, DownloadedPaths, ScopedTaint


class _Kit:
    @staticmethod
    def stmt(source: str) -> ast.AST:
        return ast.parse(source).body[0]

    @staticmethod
    def call(source: str) -> ast.Call:
        node = ast.parse(source, mode="eval").body
        assert isinstance(node, ast.Call)
        return node


class TestBindingForms:
    def test_a_starred_target_names_what_it_collects(self) -> None:
        target = _Kit.stmt("first, *rest = x").targets[0]  # type: ignore[attr-defined]
        assert BindingForms.names(target) == ["first", "rest"]

    def test_a_node_of_another_kind_binds_nothing_through_each_form(self) -> None:
        other = _Kit.stmt("pass")
        for form in (
            BindingForms.assign,
            BindingForms.annotated,
            BindingForms.walrus,
            BindingForms.with_items,
            BindingForms.for_target,
        ):
            assert list(form(other)) == []

    def test_each_form_names_what_it_binds_and_the_value_it_gets(self) -> None:
        [(names, _)] = list(BindingForms.for_target(_Kit.stmt("for a, b in pairs: pass")))
        assert names == ["a", "b"]
        [(names, _)] = list(BindingForms.with_items(_Kit.stmt("with open(p) as handle: pass")))
        assert names == ["handle"]
        [(names, _)] = list(BindingForms.annotated(_Kit.stmt("x: int = 1")))
        assert names == ["x"]


class TestParametersAndCalls:
    def taint(self, source: str) -> ScopedTaint:
        return ScopedTaint(ast.parse(source))

    def test_extra_positional_and_keyword_arguments_go_to_the_variable_parameters(self) -> None:
        source = "def f(a, *rest, **extra):\n    pass\nf(1, 2, 3, key=4)\n"
        tree = ast.parse(source)
        taint = ScopedTaint(tree)
        function = tree.body[0]
        call = tree.body[1].value  # type: ignore[attr-defined]
        pairs = {name for name, _ in taint._pairs(call, function)}
        assert pairs == {"a", "rest", "extra"}

    def test_an_argument_with_no_parameter_to_take_it_is_dropped(self) -> None:
        source = "def f(a):\n    pass\nf(1, 2, key=3)\n"
        tree = ast.parse(source)
        taint = ScopedTaint(tree)
        pairs = taint._pairs(tree.body[1].value, tree.body[0])  # type: ignore[attr-defined]
        assert [name for name, _ in pairs] == ["a"]

    def test_the_values_of_a_name_that_is_not_a_function_parameter_are_none(self) -> None:
        tree = ast.parse("print(unbound)\n")
        taint = ScopedTaint(tree)
        name = tree.body[0].value.args[0]  # type: ignore[attr-defined]
        assert taint.values_of(name) == []


class TestOpenCalls:
    def test_each_open_form_names_its_path_and_whether_it_writes(self) -> None:
        path, writes = DownloadedPaths.opened(_Kit.call("open(p, 'w')"))  # type: ignore[misc]
        assert writes is True
        path, writes = DownloadedPaths.opened(_Kit.call("io.open(p)"))  # type: ignore[misc]
        assert writes is False
        path, writes = DownloadedPaths.opened(_Kit.call("target.open(mode='a')"))  # type: ignore[misc]
        assert (ast.unparse(path), writes) == ("target", True)

    def test_a_module_open_with_no_arguments_and_other_calls_name_no_path(self) -> None:
        assert DownloadedPaths.opened(_Kit.call("os.open()")) is None
        assert DownloadedPaths.opened(_Kit.call("print(p)")) is None
