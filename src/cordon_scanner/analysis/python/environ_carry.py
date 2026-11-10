"""Which expressions hold the whole environment, as opposed to one setting read from it.

`PythonFacts.carried` answers "does this expression contain the source anywhere", which is right
for a hostname and wrong for a mapping: `env.get("KEY")` contains `env` and yields one value. Read
that way, `environ = os.environ if environ is None else environ` followed by `environ.get(name)`
sent "the whole environment" with every request the file made (reviews/pypi-98/
17-EXFIL-SCANNER-ERRORS.md: nine legitimate packages, three shapes).

Here an expression is whole when it can carry every variable:

* `os.environ` itself, a name assigned from a whole value, a parameter a whole value is handed to;
* a container, a spread (`{**env}`), a comprehension over one, or a method that is not a keyed read
  (`env.items()`, `env.copy()`), or any call this file cannot see into with a whole argument;
* a call to a function of this file that returns a whole value, or that is handed one and does
  anything with it but read single keys.

It is one value when it is a keyed read of a whole value -- `env[k]`, `env.get(k)`,
`env.setdefault(k)`, `env.pop(k)`, `k in env`, or `os.environ(k)` written as a call -- and nothing
else. A helper that only reads keys from what it is handed returns one value; one that passes it
anywhere else, encodes it or returns it stays whole, and an unknown callee always does.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from cordon_scanner.analysis.python.pysyntax import PythonSyntax

if TYPE_CHECKING:
    from collections.abc import Callable

#: Methods of a mapping that return one value, not the mapping.
KEYED_METHODS = frozenset({"get", "setdefault", "pop", "__getitem__", "__contains__"})

#: Calls that start a child process, by module and function. Their `env=` is the child's.
SPAWNS: frozenset[tuple[str, str]] = frozenset(
    {
        ("subprocess", "Popen"),
        ("subprocess", "run"),
        ("subprocess", "call"),
        ("subprocess", "check_call"),
        ("subprocess", "check_output"),
        ("asyncio", "create_subprocess_exec"),
        ("asyncio", "create_subprocess_shell"),
    }
)


class EnvironmentCarry:
    """`carried` for the whole environment, keyed-read aware. Same signature as
    `PythonFacts.carried`'s result: `holds(node, deep=True)`."""

    @classmethod
    def carried(
        cls,
        tree: ast.AST,
        is_environ: Callable[[ast.AST], bool],
        spawns: Callable[[ast.Call], bool] | None = None,
    ) -> Callable[..., bool]:
        """`is_environ(node)`: whether a node is `os.environ` (or `os.environb`) as a value.
        `spawns(call)`: whether a call starts a child process, resolved through the file's
        imports by the caller; `is_spawn` (no imports) when not given."""
        starts_child = spawns or cls.is_spawn
        scope = PythonSyntax.name_scope(tree)
        passed = PythonSyntax.passed(tree)
        functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {
            f.name: f for f in PythonSyntax.of(tree, ast.FunctionDef, ast.AsyncFunctionDef)
        }
        carrying: set[tuple[int, str]] = set()
        returning: set[str] = set()

        def whole(node: ast.AST) -> bool:
            if is_environ(node):
                return True
            if isinstance(node, ast.Name):
                return (scope(node, node.id), node.id) in carrying
            if isinstance(node, ast.Subscript):
                return not whole(node.value) and whole(node.slice)
            # A comparison that is itself sent (`{"ci": "CI" in env}`, `any(k in env for k in
            # markers)`) still tells the receiver what the environment holds; one that only
            # steers control flow is never a sent value (runtime-readout, review 2026-11-10).
            if isinstance(node, ast.Call):
                return call_whole(node)
            return any(whole(child) for child in ast.iter_child_nodes(node))

        def call_whole(call: ast.Call) -> bool:
            func = call.func
            if is_environ(func):
                return False  # `os.environ("KEY")`: one value, if it runs at all
            if isinstance(func, ast.Attribute) and whole(func.value):
                return func.attr not in KEYED_METHODS
            # A child process's `env=` is consumed by the child: the Popen or CompletedProcess
            # that comes back is not the environment (pull-request-view, review 2026-11-09).
            spawned = starts_child(call)
            arguments = [
                *call.args,
                *(k.value for k in call.keywords if not (spawned and k.arg == "env")),
            ]
            name = cls._callee(call)
            local = functions.get(name) if name is not None else None
            if local is None:
                return any(whole(a) for a in arguments) or whole(func)
            if name in returning:
                return True
            return any(
                whole(argument) and not cls._reads_keys_only(local, param, functions, whole, set())
                for argument, param in cls._bindings(call, local)
            )

        for _ in range(3):
            carrying.update((function, param) for arg, function, param in passed if whole(arg))
            for node in PythonSyntax.nodes(tree):
                if isinstance(node, ast.Assign) and whole(node.value):
                    carrying.update(
                        (scope(t, t.id), t.id) for t in node.targets if isinstance(t, ast.Name)
                    )
                elif (
                    isinstance(node, ast.AnnAssign)
                    and node.value is not None
                    and isinstance(node.target, ast.Name)
                    and whole(node.value)
                ):
                    carrying.add((scope(node.target, node.target.id), node.target.id))
            for function in functions.values():
                if function.name not in returning and any(
                    part.value is not None and whole(part.value)
                    for part in PythonSyntax.within(function, ast.Return)
                ):
                    returning.add(function.name)

        def holds(node: ast.AST, *, deep: bool = True) -> bool:
            del deep  # a mapping is held structurally, never by containment alone
            return whole(node)

        return holds

    @staticmethod
    def is_spawn(call: ast.Call) -> bool:
        """`subprocess.Popen(...)` and its kin, or `Popen(...)` imported bare."""
        func = call.func
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            return (func.value.id, func.attr) in SPAWNS
        return isinstance(func, ast.Name) and func.id in {"Popen", "check_output", "check_call"}

    @staticmethod
    def _callee(call: ast.Call) -> str | None:
        func = call.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            return func.attr
        return None

    @staticmethod
    def _bindings(
        call: ast.Call, function: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> list[tuple[ast.AST, str | None]]:
        """Each argument with the parameter it binds; None when it binds none this can name
        (`*args`, `**kwargs`, a starred argument), which `_reads_keys_only` treats as unknown."""
        params = [a.arg for a in (*function.args.posonlyargs, *function.args.args)]
        if isinstance(call.func, ast.Attribute) and params[:1] in (["self"], ["cls"]):
            params = params[1:]
        out: list[tuple[ast.AST, str | None]] = []
        for index, argument in enumerate(call.args):
            starred = isinstance(argument, ast.Starred)
            out.append((argument, None if starred or index >= len(params) else params[index]))
        known = {*params, *(a.arg for a in function.args.kwonlyargs)}
        out.extend((k.value, k.arg if k.arg in known else None) for k in call.keywords)
        return out

    @classmethod
    def _reads_keys_only(
        cls,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
        param: str | None,
        functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
        is_whole: Callable[[ast.AST], bool],
        seen: set[tuple[str, str]],
    ) -> bool:
        """Whether every use of `param` in `function` reads a single key from it.

        Allowed: `p[k]`, `p.get(k)` and its kin, `k in p`, `p is None`, rebinding it to itself
        or the environment (`p = os.environ if p is None else p`), and handing it to a function
        of this file whose parameter is used the same way. Anything else -- returned, iterated,
        spread, serialised, handed to a function this file cannot see -- is not. `seen` stops a
        recursion through mutually calling helpers, answering "not keyed-only" when it loops."""
        if param is None or (function.name, param) in seen:
            return False
        seen.add((function.name, param))
        parents = PythonSyntax.parents(function)
        for use in (n for n in PythonSyntax.within(function, ast.Name) if n.id == param):
            parent = parents.get(id(use))
            if isinstance(use.ctx, ast.Store):
                if cls._rebinds_to_itself(parent, use, param, is_whole):
                    continue
                return False
            if not isinstance(use.ctx, ast.Load):
                return False
            if cls._keyed_use(use, parent, parents) or cls._is_none_check(use, parent):
                continue
            if cls._self_or_environ(parent, param, is_whole, use, parents):
                continue
            if (isinstance(parent, ast.Call) and use in parent.args) or isinstance(
                parent, ast.keyword
            ):
                call = parent if isinstance(parent, ast.Call) else parents.get(id(parent))
                name = cls._callee(call) if isinstance(call, ast.Call) else None
                local = functions.get(name) if name is not None else None
                if local is not None and isinstance(call, ast.Call):
                    bound = {id(a): p for a, p in cls._bindings(call, local)}
                    if cls._reads_keys_only(local, bound.get(id(use)), functions, is_whole, seen):
                        continue
            return False
        return True

    @staticmethod
    def _keyed_use(use: ast.Name, parent: ast.AST | None, parents: dict[int, ast.AST]) -> bool:
        if isinstance(parent, ast.Subscript) and parent.value is use:
            return True
        if isinstance(parent, ast.Compare) and use in parent.comparators:
            return all(isinstance(op, (ast.In, ast.NotIn)) for op in parent.ops)
        return (
            isinstance(parent, ast.Attribute)
            and parent.value is use
            and parent.attr in KEYED_METHODS
            and isinstance(parents.get(id(parent)), ast.Call)
        )

    @staticmethod
    def _is_none_check(use: ast.Name, parent: ast.AST | None) -> bool:
        return (
            isinstance(parent, ast.Compare)
            and parent.left is use
            and all(isinstance(op, (ast.Is, ast.IsNot)) for op in parent.ops)
            and all(isinstance(c, ast.Constant) and c.value is None for c in parent.comparators)
        )

    @staticmethod
    def _self_or_environ(
        node: ast.AST | None,
        param: str,
        is_whole: Callable[[ast.AST], bool],
        use: ast.Name,
        parents: dict[int, ast.AST],
    ) -> bool:
        """`use` is a branch of `p if p is not None else os.environ` or `p or os.environ` that is
        itself assigned back to `p`: the same mapping under the same name."""
        if not isinstance(node, (ast.IfExp, ast.BoolOp)):
            return False
        assign = parents.get(id(node))
        if not (
            isinstance(assign, ast.Assign)
            and len(assign.targets) == 1
            and isinstance(assign.targets[0], ast.Name)
            and assign.targets[0].id == param
        ):
            return False
        branches = [node.body, node.orelse] if isinstance(node, ast.IfExp) else node.values
        return use in branches and all(
            (isinstance(b, ast.Name) and b.id == param) or is_whole(b) for b in branches
        )

    @classmethod
    def _rebinds_to_itself(
        cls,
        assign: ast.AST | None,
        target: ast.Name,
        param: str,
        is_whole: Callable[[ast.AST], bool],
    ) -> bool:
        """`p = os.environ if p is None else p`, `p = p or os.environ`, `p = self.environ()` when
        that returns the whole environment: still a whole mapping, still read only by key."""
        if not isinstance(assign, ast.Assign) or assign.targets != [target]:
            return False
        value = assign.value
        if isinstance(value, ast.IfExp):
            branches = [value.body, value.orelse]
        elif isinstance(value, ast.BoolOp):
            branches = list(value.values)
        else:
            return is_whole(value)
        return all((isinstance(b, ast.Name) and b.id == param) or is_whole(b) for b in branches)


__all__ = ["KEYED_METHODS", "SPAWNS", "EnvironmentCarry"]
