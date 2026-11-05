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
from typing import TYPE_CHECKING, ClassVar

Label = int


class ValueFlowSteps:
    """What `PythonValueFlow` does at each kind of node, chosen by the tables INDEX, TAINT and
    FLOW: indexing scopes and calls, reading the seeds an expression carries, and moving values
    through assignments, loops, returns and calls. Part of `PythonValueFlow`, whose state these
    read."""

    vars: dict[tuple[int, str], set[Label]]
    returns: dict[str, set[Label]]
    functions: dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]]
    local: dict[int, set[str]]
    calls: list[ast.Call]

    if TYPE_CHECKING:

        @staticmethod
        def params(fn: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda) -> list[ast.arg]: ...

        def _key(self, name: str, node: ast.AST) -> tuple[int, str]: ...

        def carries(self, node: ast.Call) -> bool: ...

        def taint(self, node: ast.AST | None) -> set[Label]: ...

        def bind(self, target: ast.AST, value: set[Label]) -> bool: ...

        def call_flow(self, node: ast.Call) -> bool: ...

        def _returned(self, node: ast.AST, value: set[Label]) -> bool: ...

        def _bind_param(self, fn: ast.AST, name: str, value: set[Label]) -> bool: ...

        def _call_flow(self, node: ast.Call) -> bool: ...

        @staticmethod
        def name(func: ast.AST) -> str | None: ...

    #: What `index` records for each kind of node, by the method that records it; a node of any
    #: other kind adds nothing but its scope. Each returns the scope its children are in.
    INDEX: ClassVar[dict[type[ast.AST], str]] = {
        ast.FunctionDef: "_index_function",
        ast.AsyncFunctionDef: "_index_function",
        ast.Lambda: "_index_function",
        ast.Name: "_index_name",
        ast.Call: "_index_call",
    }

    def _index_function(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda, scope: int
    ) -> int:
        inner = id(node)
        self.local[inner] = {a.arg for a in self.params(node)}
        if not isinstance(node, ast.Lambda):
            self.functions.setdefault(node.name, []).append(node)
        return inner

    def _index_name(self, node: ast.Name, scope: int) -> int:
        if isinstance(node.ctx, ast.Store):
            self.local.setdefault(scope, set()).add(node.id)
        return scope

    def _index_call(self, node: ast.Call, scope: int) -> int:
        self.calls.append(node)
        return scope

    #: What `taint` reads from each kind of node, by the method that reads it into `out`; each
    #: returns whether the node's parts carry their seeds on.
    TAINT: ClassVar[dict[type[ast.AST], str]] = {
        ast.Name: "_taint_name",
        ast.Attribute: "_taint_attribute",
        ast.Call: "_taint_call",
    }

    def _taint_name(self, part: ast.Name, out: set[Label]) -> bool:
        out |= self.vars.get(self._key(part.id, part), set())
        return True

    def _taint_attribute(self, part: ast.Attribute, out: set[Label]) -> bool:
        out |= self.vars.get((0, part.attr), set())
        return True

    def _taint_call(self, part: ast.Call, out: set[Label]) -> bool:
        name = self.name(part.func)
        if name in self.functions:
            out |= self.returns.get(name, set())
        return self.carries(part)

    #: How a value flows through each kind of node, by the method that moves it; each returns
    #: whether anything new was bound.
    FLOW: ClassVar[dict[type[ast.AST], str]] = {
        ast.Assign: "_flow_assign",
        ast.AnnAssign: "_flow_target",
        ast.AugAssign: "_flow_target",
        ast.NamedExpr: "_flow_target",
        ast.For: "_flow_iteration",
        ast.AsyncFor: "_flow_iteration",
        ast.comprehension: "_flow_iteration",
        ast.withitem: "_flow_with",
        ast.Return: "_flow_returned",
        ast.Yield: "_flow_returned",
        ast.FunctionDef: "_flow_defaults",
        ast.AsyncFunctionDef: "_flow_defaults",
        ast.Call: "_flow_call",
    }

    def _flow_assign(self, node: ast.Assign) -> bool:
        value = self.taint(node.value)
        changed = False
        for target in node.targets:
            changed |= self.bind(target, value)
        return changed

    def _flow_target(self, node: ast.AnnAssign | ast.AugAssign | ast.NamedExpr) -> bool:
        return self.bind(node.target, self.taint(node.value))

    def _flow_iteration(self, node: ast.For | ast.AsyncFor | ast.comprehension) -> bool:
        return self.bind(node.target, self.taint(node.iter))

    def _flow_with(self, node: ast.withitem) -> bool:
        if node.optional_vars is None:
            return False
        return self.bind(node.optional_vars, self.taint(node.context_expr))

    def _flow_returned(self, node: ast.Return | ast.Yield) -> bool:
        if node.value is None:
            return False
        return self._returned(node, self.taint(node.value))

    def _flow_defaults(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        defaults = [*node.args.defaults, *(d for d in node.args.kw_defaults if d)]
        value = set().union(*(self.taint(d) for d in defaults))
        changed = False
        for param in self.params(node):
            changed |= self._bind_param(node, param.arg, value)
        return changed

    def _flow_call(self, node: ast.Call) -> bool:
        return self._call_flow(node) | self.call_flow(node)


class PythonValueFlow(ValueFlowSteps):
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
            indexer = self.INDEX.get(type(node))
            inner = getattr(self, indexer)(node, scope) if indexer else scope
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
            else:
                reader = self.TAINT.get(type(part))
                if reader is not None and not getattr(self, reader)(part, out):
                    continue  # a call that does not carry its arguments' seeds
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
                mover = self.FLOW.get(type(node))
                if mover is not None:
                    changed |= getattr(self, mover)(node)
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
