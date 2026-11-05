"""A sort, `min` or `max` over a set breaks its ties on the element, so its answer does not follow
the process's hash seed.

A set's iteration order follows the seed Python draws for each process. A keyed sort keeps that
order for the elements its key calls equal, and `min` and `max` return the first of them, so a scan
said "Upgrade past 1.3" in one run and "1.3.0" in the next (#32). The scale-floor comparison found it
on 6 of 6,400 units, all large Gradle projects; a rule finds it before a corpus has to.

The rule reads each function: a value is a set when it is built as one (`set(...)`, `frozenset(...)`,
a set display or comprehension, a set operator, `.union(...)`), assigned from one, or annotated as
one (a parameter, a local, a class attribute), and a generator over a set is one too. A keyed call
over such a value passes only if its key is total by construction: a lambda whose result is the
element or a tuple ending in it (`key=lambda v: (len(v), v)`), or a function in the module whose
every return is such a tuple. A key that is total for another reason is listed below, with that
reason. A sort without a key over strings or numbers is total already and is not read.

A sort over a dict or a list keeps their order, which no seed changes, so the rule leaves those.
"""

from __future__ import annotations

import ast
from pathlib import Path

from support import ROOT

PACKAGES = (ROOT / "src" / "cordon_scanner", ROOT / "src" / "cordon_sandbox")
SET_TYPES = {"set", "frozenset", "Set", "AbstractSet", "FrozenSet", "MutableSet"}
SET_METHODS = {"union", "intersection", "difference", "symmetric_difference"}

#: `path:function` -> why the key is total there though the rule cannot see it.
TOTAL_FOR_ANOTHER_REASON: dict[str, str] = {}


class SetValues:
    """Which expressions in one function are sets."""

    def __init__(self, names: set[str]) -> None:
        self.names = names

    @staticmethod
    def annotated(annotation: ast.expr | None) -> bool:
        if annotation is None:
            return False
        text = ast.unparse(annotation).strip("'\"")
        return text.split("[", 1)[0].rsplit(".", 1)[-1] in SET_TYPES

    def holds(self, value: ast.expr) -> bool:
        if isinstance(value, (ast.Set, ast.SetComp)):
            return True
        if isinstance(value, ast.Call):
            if isinstance(value.func, ast.Name) and value.func.id in {"set", "frozenset"}:
                return True
            if isinstance(value.func, ast.Attribute) and value.func.attr in SET_METHODS:
                return True
        if isinstance(value, ast.Name):
            return value.id in self.names
        if isinstance(value, ast.Attribute):
            return value.attr in self.names
        if isinstance(value, ast.BinOp) and isinstance(
            value.op, (ast.BitOr, ast.BitAnd, ast.Sub, ast.BitXor)
        ):
            return self.holds(value.left) or self.holds(value.right)
        if isinstance(value, (ast.GeneratorExp, ast.ListComp)):
            return any(self.holds(g.iter) for g in value.generators)
        return False


class TotalSorts:
    """The keyed sorts over sets in one module whose key the rule cannot show is total."""

    @staticmethod
    def ends_in(result: ast.expr, parameter: str) -> bool:
        if isinstance(result, ast.Tuple) and result.elts:
            result = result.elts[-1]
        return isinstance(result, ast.Name) and result.id == parameter

    @staticmethod
    def total_functions(tree: ast.Module) -> set[str]:
        """Functions every return of which is the first parameter or a tuple ending in it."""
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.args.args:
                parameter = node.args.args[0].arg
                returns = [r for r in ast.walk(node) if isinstance(r, ast.Return)]
                if returns and all(
                    r.value is not None and TotalSorts.ends_in(r.value, parameter) for r in returns
                ):
                    names.add(node.name)
        return names

    @staticmethod
    def total(key: ast.expr, functions: set[str]) -> bool:
        if isinstance(key, ast.Lambda) and key.args.args:
            return TotalSorts.ends_in(key.body, key.args.args[0].arg)
        if isinstance(key, ast.Name):
            return key.id in functions
        return isinstance(key, ast.Attribute) and key.attr in functions

    @staticmethod
    def own(scope: ast.AST) -> list[ast.AST]:
        """The scope's nodes, leaving out the functions defined in it: each is its own scope."""
        nested = {
            id(inner)
            for node in ast.iter_child_nodes(scope)
            for child in ast.walk(node)
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            for inner in ast.walk(child)
        }
        return [n for n in ast.walk(scope) if id(n) not in nested]

    @staticmethod
    def found(path: Path) -> list[str]:
        return TotalSorts.found_in(path, path.relative_to(ROOT).as_posix())

    @staticmethod
    def found_in(path: Path, relative: str = "") -> list[str]:
        relative = relative or path.name
        tree = ast.parse(path.read_text(encoding="utf-8"))
        attributes = {
            target.attr if isinstance(target, ast.Attribute) else target.id
            for node in ast.walk(tree)
            if isinstance(node, ast.AnnAssign) and SetValues.annotated(node.annotation)
            for target in [node.target]
            if isinstance(target, (ast.Attribute, ast.Name))
        }
        functions = TotalSorts.total_functions(tree)
        out = []
        scopes = [
            n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        for scope in [tree, *scopes]:
            nodes = TotalSorts.own(scope)
            values = SetValues(set(attributes))
            if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
                arguments = [*scope.args.posonlyargs, *scope.args.args, *scope.args.kwonlyargs]
                values.names |= {a.arg for a in arguments if SetValues.annotated(a.annotation)}
            # Twice, so a set assigned from a set assigned later in the text is seen too.
            for _ in range(2):
                for node in nodes:
                    if isinstance(node, ast.Assign) and values.holds(node.value):
                        values.names |= {t.id for t in node.targets if isinstance(t, ast.Name)}
                    elif (
                        isinstance(node, ast.AnnAssign)
                        and isinstance(node.target, ast.Name)
                        and (
                            SetValues.annotated(node.annotation)
                            or (node.value is not None and values.holds(node.value))
                        )
                    ):
                        values.names.add(node.target.id)
            name = getattr(scope, "name", "<module>")
            if f"{relative}:{name}" in TOTAL_FOR_ANOTHER_REASON:
                continue
            for node in nodes:
                if not isinstance(node, ast.Call) or not node.args:
                    continue
                func = node.func
                called = func.id if isinstance(func, ast.Name) else ""
                if called not in {"sorted", "min", "max"}:
                    continue
                key = next((k.value for k in node.keywords if k.arg == "key"), None)
                if key is None or not values.holds(node.args[0]):
                    continue
                if not TotalSorts.total(key, functions):
                    out.append(f"{relative}:{node.lineno} {name}: {ast.unparse(node)[:100]}")
        return sorted(set(out))


class TestTotalSorts:
    def test_every_keyed_sort_over_a_set_breaks_ties_on_the_element(self) -> None:
        found = [
            line
            for package in PACKAGES
            for path in sorted(package.rglob("*.py"))
            for line in TotalSorts.found(path)
        ]
        assert not found, (
            "a keyed sort, min or max over a set whose key can call two elements equal; end the "
            "key in the element (`key=lambda v: (len(v), v)`) or list why it is total:\n"
            + "\n".join(found)
        )

    def test_the_exceptions_still_exist(self) -> None:
        for entry in TOTAL_FOR_ANOTHER_REASON:
            path, _, function = entry.partition(":")
            source = (ROOT / path).read_text(encoding="utf-8")
            assert f"def {function}(" in source, f"{entry} is listed but no longer there"

    def test_the_rule_finds_the_defects_it_was_written_for(self, tmp_path: Path) -> None:
        """Each of the forms #32 and the rule engine's literal runs fixed, written the old way."""
        module = tmp_path / "old.py"
        module.write_text(
            "from functools import cmp_to_key\n"
            "def literals(found: list[bytes]):\n"
            "    return sorted(set(found), key=len)\n"
            "def runs(found):\n"
            "    return sorted(set(found), key=lambda r: -len(r))\n"
            "def names(products: set[str]):\n"
            "    return sorted((p.split(':')[0] for p in products), key=len)\n"
            "def fixed(records, compare):\n"
            "    order = cmp_to_key(compare)\n"
            "    return sorted({r.fixed for r in records}, key=order)\n"
            "def first(versions: frozenset[str]):\n"
            "    return min(versions, key=len)\n",
            encoding="utf-8",
        )
        found = TotalSorts.found_in(module)
        assert {line.split(" ", 1)[1].split(":")[0] for line in found} == {
            "literals",
            "runs",
            "names",
            "fixed",
            "first",
        }
        assert len(found) == 5

    def test_the_rule_passes_total_keys_and_ordered_inputs(self, tmp_path: Path) -> None:
        module = tmp_path / "new.py"
        module.write_text(
            "def by_length(value):\n"
            "    return len(value), value\n"
            "def literals(found):\n"
            "    return sorted(set(found), key=lambda b: (len(b), b))\n"
            "def named(found):\n"
            "    return sorted(set(found), key=by_length)\n"
            "def ordered(bindings: dict[str, int]):\n"
            "    return sorted(bindings, key=len)\n"
            "def plain(found):\n"
            "    return sorted(set(found))\n",
            encoding="utf-8",
        )
        assert TotalSorts.found_in(module) == []
