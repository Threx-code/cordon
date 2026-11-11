"""The value a module computes from its own literals alone, folded without running.

easyIoCtl 1.0's `start.py` holds a 100-character alphabet and a list of 13 indices, adds
`alphabet[i]` for each index to an empty string in a `for` loop, and hands the result to `exec`.
openblox 1.0.0's `setup.py` returns `"".join(chr(t + base) for t in [...])` from a helper, and runs
the command it heads with `subprocess.check_output` at install. Neither program appears anywhere as
a literal, so nothing that reads literals reads it; but every value the computation touches is a
literal of the file, so the program is fixed and can be computed. A computed literal is still a
literal (`ExecutionFlows._written_text`, `ComputedCommands`).

`LiteralProgram.folded(tree, node)`: the string an expression evaluates to, given the module's
top-level statements that end before its line, and whether computing it took a step that serves
only to hide a text: `chr`, picking single characters out of a string, a stepped slice, `reversed`,
XOR. Joining or adding literals hides nothing (`"pip " + "install"`) and is not flagged.

Modelled: assignments, `+=`, `for` over a computed sequence, `if` on a computed test, `try`,
`list.append`,
and the return of a same-file function called with no arguments; expressions built from str, bytes
and int literals, lists and tuples of them, indexing and slicing, arithmetic, comparisons, `chr`,
`str`, `len`, `map`, `reversed`, `"".join` of a sequence or a one-clause comprehension, and
`.decode()`. Anything else makes the value unknown. Bounded: at most `STEPS` evaluations, `DEPTH`
nested function returns and `MAX_TEXT` characters in any value, so a file cannot make the folding
expensive. Nothing is run, imported or decoded beyond these operations.
"""

from __future__ import annotations

import ast
import operator
from collections.abc import Callable
from typing import Any, ClassVar

from cordon_scanner.analysis.python.pysyntax import PythonSyntax

#: The environment key holding the names whose folded value took a hiding step.
_MARKS = "\x00concealed"


class _Unknown(Exception):
    """A value the literals alone do not determine, or one past the budget."""


class _Returned(Exception):
    """A folded function's `return`, carrying its value."""

    def __init__(self, value: Any) -> None:
        super().__init__()
        self.value = value


class LiteralExpressions:
    """Evaluates one expression over folded names; records whether a hiding step was taken."""

    STEPS: ClassVar[int] = 200_000
    MAX_TEXT: ClassVar[int] = 128 * 1024
    DEPTH: ClassVar[int] = 3
    _ATOMS: ClassVar[tuple[type, ...]] = (str, bytes, int)
    _INTEGER_OPS: ClassVar[dict[type, Callable[[int, int], int]]] = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Mod: operator.mod,
        ast.FloorDiv: operator.floordiv,
        ast.BitXor: operator.xor,
    }
    _COMPARISONS: ClassVar[dict[type, Callable[[Any, Any], bool]]] = {
        ast.Eq: operator.eq,
        ast.NotEq: operator.ne,
        ast.Lt: operator.lt,
        ast.LtE: operator.le,
        ast.Gt: operator.gt,
        ast.GtE: operator.ge,
    }

    def __init__(self, functions: dict[str, ast.FunctionDef], depth: int = 0) -> None:
        self._steps = 0
        self.concealed = False
        self._functions = functions
        self._depth = depth

    @staticmethod
    def _known(env: dict[str, Any], name: str) -> Any:
        if name not in env:
            raise _Unknown
        return env[name]

    def _bounded(self, value: Any) -> Any:
        if isinstance(value, str | bytes | list) and len(value) > self.MAX_TEXT:
            raise _Unknown
        return value

    def _expr(self, node: ast.AST, env: dict[str, Any]) -> Any:
        self._steps += 1
        if self._steps > self.STEPS:
            raise _Unknown
        handler = self._EXPRESSIONS.get(type(node))
        if handler is None:
            raise _Unknown
        return handler(self, node, env)

    def _constant(self, node: ast.Constant, env: dict[str, Any]) -> Any:
        if isinstance(node.value, self._ATOMS) and not isinstance(node.value, bool):
            return node.value
        raise _Unknown

    def _name(self, node: ast.Name, env: dict[str, Any]) -> Any:
        # A name computed with a hiding step by an earlier statement hides what reads it.
        self.concealed |= node.id in env.get(_MARKS, ())
        return self._known(env, node.id)

    def _items(self, node: ast.List | ast.Tuple, env: dict[str, Any]) -> Any:
        return [self._expr(e, env) for e in node.elts]

    def _unary(self, node: ast.UnaryOp, env: dict[str, Any]) -> Any:
        operand = self._expr(node.operand, env)
        if not isinstance(operand, int) or not isinstance(node.op, ast.USub | ast.UAdd):
            raise _Unknown
        return -operand if isinstance(node.op, ast.USub) else operand

    def _binop_node(self, node: ast.BinOp, env: dict[str, Any]) -> Any:
        return self._binop(node.op, self._expr(node.left, env), self._expr(node.right, env))

    def _binop(self, op: ast.operator, left: Any, right: Any) -> Any:
        if isinstance(left, int) and isinstance(right, int):
            apply = self._INTEGER_OPS.get(type(op))
            if apply is None or (isinstance(op, ast.Mod | ast.FloorDiv) and right == 0):
                raise _Unknown
            self.concealed |= isinstance(op, ast.BitXor)
            return apply(left, right)
        if (
            isinstance(op, ast.Add)
            and type(left) is type(right)
            and isinstance(left, str | bytes | list)
        ):
            return self._bounded(left + right)
        if (
            isinstance(op, ast.Mult)
            and isinstance(right, int)
            and isinstance(left, str | bytes | list)
        ):
            if right * len(left) > self.MAX_TEXT:
                raise _Unknown
            return left * right
        raise _Unknown

    def _compare(self, node: ast.Compare, env: dict[str, Any]) -> Any:
        if len(node.ops) != 1:
            raise _Unknown
        compare = self._COMPARISONS.get(type(node.ops[0]))
        left, right = self._expr(node.left, env), self._expr(node.comparators[0], env)
        if compare is None or type(left) is not type(right):
            raise _Unknown
        return int(compare(left, right))

    def _ifexp(self, node: ast.IfExp, env: dict[str, Any]) -> Any:
        return self._expr(node.body if self._expr(node.test, env) else node.orelse, env)

    def _subscript(self, node: ast.Subscript, env: dict[str, Any]) -> Any:
        value = self._expr(node.value, env)
        if not isinstance(value, str | bytes | list):
            raise _Unknown
        index = node.slice
        try:
            if isinstance(index, ast.Slice):
                parts = [
                    None if p is None else self._expr(p, env)
                    for p in (index.lower, index.upper, index.step)
                ]
                if any(p is not None and not isinstance(p, int) for p in parts) or parts[2] == 0:
                    raise _Unknown
                self.concealed |= parts[2] not in (None, 1)
                return value[slice(*parts)]
            position = self._expr(index, env)
            if not isinstance(position, int):
                raise _Unknown
            # One character picked out of a text: an alphabet indexed to spell another.
            self.concealed |= isinstance(value, str | bytes)
            return value[position]
        except IndexError as error:
            raise _Unknown from error

    def _call(self, node: ast.Call, env: dict[str, Any]) -> Any:
        if node.keywords:
            raise _Unknown
        func = node.func
        if isinstance(func, ast.Name):
            if func.id in self._BUILTINS and len(node.args) == 1:
                return self._BUILTINS[func.id](self, self._expr(node.args[0], env))
            if func.id == "map" and len(node.args) == 2:
                return self._mapped(node.args[0], self._expr(node.args[1], env))
            if func.id in self._functions and not node.args:
                return self._returned(self._functions[func.id], env)
            raise _Unknown
        if isinstance(func, ast.Attribute) and func.attr == "join" and len(node.args) == 1:
            separator = self._expr(func.value, env)
            pieces = self._sequence(node.args[0], env)
            if not isinstance(separator, str) or not all(isinstance(p, str) for p in pieces):
                raise _Unknown
            return self._bounded(separator.join(pieces))
        if isinstance(func, ast.Attribute) and func.attr == "decode" and not node.args:
            data = self._expr(func.value, env)
            if isinstance(data, bytes):
                return data.decode("utf-8", "replace")
        raise _Unknown

    def _chr(self, argument: Any) -> Any:
        if not isinstance(argument, int) or not 0 <= argument <= 0x10FFFF:
            raise _Unknown
        self.concealed = True
        return chr(argument)

    def _reversed(self, argument: Any) -> Any:
        if not isinstance(argument, str | bytes | list):
            raise _Unknown
        self.concealed = True
        return list(reversed(argument))

    def _str(self, argument: Any) -> Any:
        if not isinstance(argument, int | str):
            raise _Unknown
        return str(argument)

    def _len(self, argument: Any) -> Any:
        if not isinstance(argument, str | bytes | list):
            raise _Unknown
        return len(argument)

    def _mapped(self, func: ast.AST, items: Any) -> list[Any]:
        if (
            not isinstance(func, ast.Name)
            or func.id not in ("chr", "str")
            or not isinstance(items, list | str)
        ):
            raise _Unknown
        return [self._BUILTINS[func.id](self, item) for item in items]

    def _sequence(self, node: ast.AST, env: dict[str, Any]) -> list[Any]:
        """A sequence `"".join` takes: a value, or a one-clause comprehension over one."""
        if isinstance(node, ast.GeneratorExp | ast.ListComp):
            if len(node.generators) != 1:
                raise _Unknown
            clause = node.generators[0]
            if clause.ifs or clause.is_async or not isinstance(clause.target, ast.Name):
                raise _Unknown
            items = self._expr(clause.iter, env)
            if not isinstance(items, list | str | bytes):
                raise _Unknown
            scope = dict(env)
            out = []
            for item in items:
                scope[clause.target.id] = item
                out.append(self._expr(node.elt, scope))
            return out
        value = self._expr(node, env)
        if not isinstance(value, list | str):
            raise _Unknown
        return list(value)

    def _returned(self, function: ast.FunctionDef, env: dict[str, Any]) -> Any:
        """What a same-file function taking no arguments returns, its body folded."""
        args = function.args
        if (
            self._depth >= self.DEPTH
            or args.args
            or args.posonlyargs
            or args.kwonlyargs
            or args.vararg
        ):
            raise _Unknown
        inner = LiteralProgram(self._functions, self._depth + 1)
        inner._steps = self._steps
        local = dict(env)
        try:
            for statement in function.body:
                inner._strict(statement, local)
        except _Returned as returned:
            self._steps = inner._steps
            self.concealed |= inner.concealed
            return returned.value
        raise _Unknown

    _BUILTINS: ClassVar[dict[str, Callable[[LiteralExpressions, Any], Any]]] = {
        "chr": _chr,
        "reversed": _reversed,
        "str": _str,
        "len": _len,
    }
    _EXPRESSIONS: ClassVar[dict[type, Callable[..., Any]]] = {
        ast.Constant: _constant,
        ast.Name: _name,
        ast.List: _items,
        ast.Tuple: _items,
        ast.UnaryOp: _unary,
        ast.BinOp: _binop_node,
        ast.Compare: _compare,
        ast.IfExp: _ifexp,
        ast.Subscript: _subscript,
        ast.Call: _call,
    }


class LiteralProgram(LiteralExpressions):
    """Folds a module's literal computation: its top-level statements, and function returns."""

    @classmethod
    def value(cls, tree: ast.AST, node: ast.AST) -> str | None:
        """The string `node` evaluates to, given the module's top-level statements before it."""
        return cls.folded(tree, node)[0]

    @classmethod
    def folded(cls, tree: ast.AST, node: ast.AST) -> tuple[str | None, bool]:
        """(the string `node` evaluates to or None, whether computing it took a hiding step)."""
        functions = cls._functions_of(tree)
        program = cls(functions)
        try:
            value = program._expr(node, dict(cls._environment(tree, getattr(node, "lineno", 0))))
        except (_Unknown, _Returned):
            return None, False
        if isinstance(value, bytes):
            value = value.decode("utf-8", "replace")
        return (value, program.concealed) if isinstance(value, str) else (None, False)

    @staticmethod
    def _functions_of(tree: ast.AST) -> dict[str, ast.FunctionDef]:
        """Module-level functions by name, each defined once."""

        def build() -> dict[str, ast.FunctionDef]:
            seen: dict[str, ast.FunctionDef | None] = {}
            for statement in getattr(tree, "body", ()):
                if isinstance(statement, ast.FunctionDef):
                    seen[statement.name] = None if statement.name in seen else statement
            return {name: f for name, f in seen.items() if f is not None}

        functions: dict[str, ast.FunctionDef] = PythonSyntax.memo(
            tree, ("literal-functions",), build
        )
        return functions

    @classmethod
    def _environment(cls, tree: ast.AST, line: int) -> dict[str, Any]:
        """Name -> folded value after the top-level statements ending before `line`. Once per
        tree and line."""

        def fold() -> dict[str, Any]:
            env: dict[str, Any] = {}
            program = cls(cls._functions_of(tree))
            for statement in getattr(tree, "body", ()):
                if (statement.end_lineno or statement.lineno) >= line:
                    break
                program._lenient(statement, env)
            return env

        folded: dict[str, Any] = PythonSyntax.memo(tree, ("literal-program", line), fold)
        return folded

    def _lenient(self, node: ast.stmt, env: dict[str, Any]) -> None:
        """A top-level statement: one the folder cannot follow forgets the names it binds."""
        try:
            self._strict(node, env)
        except (_Unknown, _Returned):
            for target in PythonSyntax.nodes(node):
                if isinstance(target, ast.Name) and isinstance(target.ctx, ast.Store):
                    env.pop(target.id, None)

    def _strict(self, node: ast.stmt, env: dict[str, Any]) -> None:
        """A statement folded exactly, or `_Unknown`."""
        handler = self._STATEMENTS.get(type(node))
        if handler is None:
            raise _Unknown
        before, self.concealed = self.concealed, False
        try:
            handler(self, node, env)
        finally:
            if self.concealed:
                bound = {
                    n.id
                    for n in PythonSyntax.nodes(node)
                    if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)
                }
                if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                    bound |= {
                        n.id for n in PythonSyntax.nodes(node.value.func) if isinstance(n, ast.Name)
                    }
                env[_MARKS] = frozenset(env.get(_MARKS, frozenset()) | bound)
            self.concealed |= before

    def _assign(self, node: ast.Assign, env: dict[str, Any]) -> None:
        if not all(isinstance(t, ast.Name) for t in node.targets):
            raise _Unknown
        value = self._expr(node.value, env)
        for target in node.targets:
            env[target.id] = value  # type: ignore[attr-defined]

    def _augassign(self, node: ast.AugAssign, env: dict[str, Any]) -> None:
        if not isinstance(node.target, ast.Name):
            raise _Unknown
        env[node.target.id] = self._binop(
            node.op, self._known(env, node.target.id), self._expr(node.value, env)
        )

    def _for(self, node: ast.For, env: dict[str, Any]) -> None:
        if not isinstance(node.target, ast.Name) or node.orelse:
            raise _Unknown
        sequence = self._expr(node.iter, env)
        if not isinstance(sequence, list | tuple | str | bytes):
            raise _Unknown
        for item in sequence:
            env[node.target.id] = item
            for statement in node.body:
                self._strict(statement, env)

    def _if(self, node: ast.If, env: dict[str, Any]) -> None:
        for statement in node.body if self._expr(node.test, env) else node.orelse:
            self._strict(statement, env)

    def _expression(self, node: ast.Expr, env: dict[str, Any]) -> None:
        """`items.append(value)`, the one call statement whose effect is a value; a docstring or
        other bare literal does nothing."""
        call = node.value
        if isinstance(call, ast.Constant):
            return
        if not (
            isinstance(call, ast.Call)
            and isinstance(call.func, ast.Attribute)
            and call.func.attr == "append"
            and isinstance(call.func.value, ast.Name)
            and len(call.args) == 1
            and not call.keywords
        ):
            raise _Unknown
        items = self._known(env, call.func.value.id)
        if not isinstance(items, list):
            raise _Unknown
        # A new list: the folded environment is shared between callers.
        env[call.func.value.id] = self._bounded([*items, self._expr(call.args[0], env)])

    def _try(self, node: ast.Try, env: dict[str, Any]) -> None:
        """A computation that folds raised nothing (a modelled failure is `_Unknown`), so the
        handlers never run: the body, then `else` and `finally`."""
        for statement in [*node.body, *node.orelse, *node.finalbody]:
            self._strict(statement, env)

    def _return(self, node: ast.Return, env: dict[str, Any]) -> None:
        raise _Returned(None if node.value is None else self._expr(node.value, env))

    _STATEMENTS: ClassVar[dict[type, Callable[..., None]]] = {
        ast.Assign: _assign,
        ast.AugAssign: _augassign,
        ast.For: _for,
        ast.If: _if,
        ast.Expr: _expression,
        ast.Return: _return,
        ast.Try: _try,
        ast.Pass: lambda self, node, env: None,
    }


__all__ = ["LiteralProgram"]
