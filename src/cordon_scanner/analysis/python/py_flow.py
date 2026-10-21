"""Where a Python value goes, over the whole file: the flow engine the persistence and decode checks
share (`py_persist.py`, `py_decoded.py`).

A subclass names its SEEDS -- the nodes whose value it follows, each labelled by its line -- and
reads its own sinks over the result. The value is followed through names (per function scope,
`global` honoured), attributes (by attribute name, across the file), containers and what is
stored into them (`paths.append(p)`), `with ... as`, loop and comprehension targets, f-strings and
any expression built from it, and the parameters and returns of the file's own functions. It
over-approximates on purpose: a value that may be carried is carried, so a sink a subclass checks
for is never missed for want of a hop. Flow-insensitive, a fixpoint over `ROUNDS` rounds.
"""

from __future__ import annotations

import ast
from typing import ClassVar

Label = int


class PythonValueFlow:
    #: Seeds followed before the file is left to the caller's fallback (`index` returns False).
    MAX_SEEDS: ClassVar[int] = 400
    #: Rounds of the fixpoint.
    ROUNDS: ClassVar[int] = 12
    #: Methods that put a value into their receiver: the receiver carries it from then on.
    STORES: ClassVar[frozenset[str]] = frozenset(
        ["append", "extend", "insert", "add", "update", "setdefault"]
    )

    def __init__(self, tree: ast.AST) -> None:
        self.tree = tree
        self.vars: dict[tuple[int, str], set[Label]] = {}
        self.returns: dict[str, set[Label]] = {}
        self.functions: dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]] = {}
        self.scope_of: dict[int, int] = {}
        self.local: dict[int, set[str]] = {}
        self.seeds: dict[int, Label] = {}
        self.calls: list[ast.Call] = []

    def seed(self, node: ast.AST) -> Label | None:
        """The label of a node whose value is followed, or None. Overridden."""
        return None

    # -- index -----------------------------------------------------------------------------------

    def index(self) -> bool:
        """Scopes, the file's functions, its calls and the seeds. False past `MAX_SEEDS`."""
        module = id(self.tree)
        self.local[module] = set()
        stack: list[tuple[ast.AST, int]] = [(self.tree, module)]
        while stack:
            node, scope = stack.pop()
            inner = scope
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
                inner = id(node)
                self.local[inner] = {a.arg for a in self.params(node)}
                if not isinstance(node, ast.Lambda):
                    self.functions.setdefault(node.name, []).append(node)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                self.local.setdefault(scope, set()).add(node.id)
            elif isinstance(node, ast.Call):
                self.calls.append(node)
            label = self.seed(node)
            if label is not None:
                self.seeds[id(node)] = label
                if len(self.seeds) > self.MAX_SEEDS:
                    return False
            self.scope_of[id(node)] = scope
            stack.extend((child, inner) for child in ast.iter_child_nodes(node))
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Global | ast.Nonlocal):
                self.local.get(self.scope_of.get(id(node), module), set()).difference_update(
                    node.names
                )
        return True

    @staticmethod
    def params(fn: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda) -> list[ast.arg]:
        a = fn.args
        out = [*a.posonlyargs, *a.args, *a.kwonlyargs]
        return out + [x for x in (a.vararg, a.kwarg) if x is not None]

    def _key(self, name: str, node: ast.AST) -> tuple[int, str]:
        scope = self.scope_of.get(id(node), id(self.tree))
        return (scope, name) if name in self.local.get(scope, ()) else (id(self.tree), name)

    # -- values ----------------------------------------------------------------------------------

    def carries(self, node: ast.Call) -> bool:
        """Whether a call's result carries what it is given. Every call does here; a subclass whose
        every other call is already a sink for what it is handed narrows it. Overridden."""
        return True

    def taint(self, node: ast.AST | None) -> set[Label]:
        """The seeds an expression's value may carry: any of its parts', through calls that
        `carries`."""
        out: set[Label] = set()
        stack = [node] if node is not None else []
        while stack:
            part = stack.pop()
            label = self.seeds.get(id(part))
            if label is not None:
                out.add(label)
            elif isinstance(part, ast.Name):
                out |= self.vars.get(self._key(part.id, part), set())
            elif isinstance(part, ast.Attribute):
                out |= self.vars.get((0, part.attr), set())
            elif isinstance(part, ast.Call):
                name = self.name(part.func)
                if name in self.functions:
                    out |= self.returns.get(name, set())
                if not self.carries(part):
                    continue
            stack.extend(ast.iter_child_nodes(part))
        return out

    def given(self, node: ast.Call, skip: frozenset[str] = frozenset()) -> set[Label]:
        """What a call's arguments carry, keywords named in `skip` left out."""
        out: set[Label] = set()
        for arg in node.args:
            out |= self.taint(arg)
        for keyword in node.keywords:
            if keyword.arg not in skip:
                out |= self.taint(keyword.value)
        return out

    def receiver(self, node: ast.Call) -> set[Label]:
        return self.taint(node.func.value) if isinstance(node.func, ast.Attribute) else set()

    def bind(self, target: ast.AST, value: set[Label]) -> bool:
        """Every name and attribute in `target` carries `value` too."""
        if not value:
            return False
        changed = False
        for part in ast.walk(target):
            key: tuple[int, str] | None = None
            if isinstance(part, ast.Name):
                key = self._key(part.id, part)
            elif isinstance(part, ast.Attribute):
                key = (0, part.attr)
            if key is not None:
                have = self.vars.setdefault(key, set())
                if not value <= have:
                    have |= value
                    changed = True
        return changed

    # -- the fixpoint ----------------------------------------------------------------------------

    def flow(self) -> None:
        nodes = list(ast.walk(self.tree))
        for _ in range(self.ROUNDS):
            changed = False
            for node in nodes:
                if isinstance(node, ast.Assign):
                    value = self.taint(node.value)
                    for target in node.targets:
                        changed |= self.bind(target, value)
                elif isinstance(node, ast.AnnAssign | ast.AugAssign | ast.NamedExpr):
                    changed |= self.bind(node.target, self.taint(node.value))
                elif isinstance(node, ast.For | ast.AsyncFor | ast.comprehension):
                    changed |= self.bind(node.target, self.taint(node.iter))
                elif isinstance(node, ast.withitem) and node.optional_vars is not None:
                    changed |= self.bind(node.optional_vars, self.taint(node.context_expr))
                elif isinstance(node, ast.Return | ast.Yield) and node.value is not None:
                    changed |= self._returned(node, self.taint(node.value))
                elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                    defaults = [*node.args.defaults, *(d for d in node.args.kw_defaults if d)]
                    value = set().union(*(self.taint(d) for d in defaults))
                    for param in self.params(node):
                        changed |= self._bind_param(node, param.arg, value)
                elif isinstance(node, ast.Call):
                    changed |= self._call_flow(node) | self.call_flow(node)
            if not changed:
                break

    def call_flow(self, node: ast.Call) -> bool:
        """A subclass's own flow at a call (a write that marks the path it writes). Overridden."""
        return False

    def _returned(self, node: ast.AST, value: set[Label]) -> bool:
        scope = self.scope_of.get(id(node))
        changed = False
        for name, fns in self.functions.items():
            if value and any(id(fn) == scope for fn in fns):
                have = self.returns.setdefault(name, set())
                if not value <= have:
                    have |= value
                    changed = True
        return changed

    def _bind_param(self, fn: ast.AST, name: str, value: set[Label]) -> bool:
        if not value:
            return False
        have = self.vars.setdefault((id(fn), name), set())
        if value <= have:
            return False
        have |= value
        return True

    def _call_flow(self, node: ast.Call) -> bool:
        """A call of the file's own function hands its arguments to every function of that name;
        a store into a container taints the container."""
        name = self.name(node.func)
        changed = False
        if name in self.functions:
            value = self.given(node)
            for fn in self.functions[name]:
                for param in self.params(fn):
                    changed |= self._bind_param(fn, param.arg, value)
        elif isinstance(node.func, ast.Attribute) and name in self.STORES:
            changed |= self.bind(node.func.value, self.given(node))
        return changed

    # -- names -----------------------------------------------------------------------------------

    @staticmethod
    def name(func: ast.AST) -> str | None:
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        return None

    @classmethod
    def dotted(cls, func: ast.AST) -> str | None:
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            base = cls.dotted(func.value)
            return f"{base}.{func.attr}" if base else None
        return None

    @staticmethod
    def command(node: ast.Call) -> str | None:
        """The command a process call runs, when every part of it is written out."""
        argv = node.args[0] if node.args else None
        if isinstance(argv, ast.Constant) and isinstance(argv.value, str):
            return argv.value
        if isinstance(argv, ast.List | ast.Tuple):
            parts = [e.value for e in argv.elts if isinstance(e, ast.Constant)]
            if len(parts) == len(argv.elts) and all(isinstance(p, str) for p in parts):
                return " ".join(str(p) for p in parts)
        return None

    #: Calls that start a process with their arguments as its command.
    PROCESS: ClassVar[frozenset[str]] = frozenset(
        [
            "subprocess.run",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
            "subprocess.Popen",
            "subprocess.getoutput",
            "subprocess.getstatusoutput",
            "os.system",
            "os.popen",
            "run",
            "call",
            "check_call",
            "check_output",
            "Popen",
            "getoutput",
            "system",
            "popen",
        ]
    )


__all__ = ["Label", "PythonValueFlow"]
