"""Which names hold what a source produced, scope by scope, and the flows between scopes.

A name bound from the network in one function is that function's own: the same name in another
function (a parameter, or a local bound from something else) is a different variable. Taking it as
the first joined a token fetched in one function to a command built in another (samsung-smartthings'
setup helper) -- and hid real flows the same way, found only when a name happened to repeat. The flows
between scopes are followed instead:

- a local function (or a method called on `self`/`cls`) whose `return` holds a sourced value makes
  every call to it sourced;
- a sourced argument passed to a local function makes that parameter sourced;
- a name a scope does not bind is its enclosing scope's (a closure, a module global); `global` and
  `nonlocal` hand the binding to the scope they name;
- a path that downloaded content was written to is a downloaded path, carried through assignments
  and through arguments in both directions (the helper that writes the file and the caller that
  named it share the path), and reading a downloaded path is reading what was downloaded:
  `fetch(url, CONFIG)` writes the response to CONFIG, `load(CONFIG)` reads it back, and the
  commands in it run.

Flow-insensitive, as the analysis around it: order inside a function is not followed.
"""

from __future__ import annotations

import ast
from collections.abc import Callable, Iterable, Iterator
from typing import ClassVar

from cordon_scanner.analysis.python.pysyntax import PythonSyntax

Function = ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda


class BindingForms:
    """Each way Python binds a name to a value, read by the node's type."""

    @staticmethod
    def assign(node: ast.AST) -> Iterator[tuple[list[str], ast.AST]]:
        if not isinstance(node, ast.Assign):
            return
        yield [t.id for t in node.targets if isinstance(t, ast.Name)], node.value

    @staticmethod
    def annotated(node: ast.AST) -> Iterator[tuple[list[str], ast.AST]]:
        if not isinstance(node, ast.AnnAssign | ast.AugAssign):
            return
        if node.value is not None and isinstance(node.target, ast.Name):
            yield [node.target.id], node.value

    @staticmethod
    def walrus(node: ast.AST) -> Iterator[tuple[list[str], ast.AST]]:
        if not isinstance(node, ast.NamedExpr):
            return
        yield [node.target.id], node.value

    @staticmethod
    def with_items(node: ast.AST) -> Iterator[tuple[list[str], ast.AST]]:
        if not isinstance(node, ast.With | ast.AsyncWith):
            return
        for item in node.items:
            if isinstance(item.optional_vars, ast.Name):
                yield [item.optional_vars.id], item.context_expr

    @staticmethod
    def for_target(node: ast.AST) -> Iterator[tuple[list[str], ast.AST]]:
        if not isinstance(node, ast.For | ast.AsyncFor):
            return
        if isinstance(node.target, ast.Name):
            yield [node.target.id], node.iter

    READERS: ClassVar[dict[type, Callable[[ast.AST], Iterator[tuple[list[str], ast.AST]]]]] = {}


BindingForms.READERS.update(
    {
        ast.Assign: BindingForms.assign,
        ast.AnnAssign: BindingForms.annotated,
        ast.AugAssign: BindingForms.annotated,
        ast.NamedExpr: BindingForms.walrus,
        ast.With: BindingForms.with_items,
        ast.AsyncWith: BindingForms.with_items,
        ast.For: BindingForms.for_target,
        ast.AsyncFor: BindingForms.for_target,
    }
)


class ScopedTaint:
    FUNCTION: ClassVar[tuple[type, ...]] = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
    ROUNDS: ClassVar[int] = 50

    #: The attribute a tree keeps its static index under: the scopes, bindings, functions, calls
    #: and returns of a file are the same for every flow that asks, so they are built once.
    INDEX: ClassVar[str] = "_cordon_scoped_index"
    #: The per-tree index's own fields, copied onto each ScopedTaint.
    STATIC: ClassVar[tuple[str, ...]] = (
        "_parents", "_tree", "_scope_cache", "_owner_cache", "_key_cache", "_locals", "_escapes",
        "_functions", "_methods", "_bindings", "_calls", "_returns", "_writers", "_mention_cache",
    )  # fmt: skip

    def __init__(self, tree: ast.AST) -> None:
        index = tree.__dict__.get(self.INDEX)
        if index is not None:
            for name, value in zip(self.STATIC, index, strict=True):
                setattr(self, name, value)
        else:
            self._index(tree)
            tree.__dict__[self.INDEX] = tuple(getattr(self, name) for name in self.STATIC)
        self._marked: set[tuple[int, str]] = set()
        self._dl = DownloadedPaths(self)
        self._returning: set[int] = set()
        #: Names bound to a dict literal with constant keys (or to a call returning one), with the
        #: keys whose values are sourced: `result["path"]` is sourced only when "path" is.
        self._keyed: dict[tuple[int, str], set[str]] = {}
        self._returning_keys: dict[int, set[str]] = {}

    def _index(self, tree: ast.AST) -> None:
        self._parents = PythonSyntax.parents(tree)
        self._owner_cache: dict[tuple[int, str], int] = {}
        self._key_cache: dict[int, tuple[int, str]] = {}
        self._mention_cache: dict[int, frozenset[str]] = {}
        self._tree = tree
        self._scope_cache: dict[int, ast.AST] = {}
        #: id(scope) -> the names that scope binds itself.
        self._locals: dict[int, set[str]] = {id(tree): set()}
        self._escapes: dict[int, set[str]] = {}
        self._functions: dict[str, list[Function]] = {}
        self._methods: set[int] = set()
        self._bindings: list[tuple[ast.AST, list[str], ast.AST]] = []
        calls: list[ast.Call] = []
        returns: list[ast.Return] = []
        readers = BindingForms.READERS
        # One pass over the file's nodes collects everything the index holds.
        for node in PythonSyntax.nodes(tree):
            kind = type(node)
            if kind is ast.Call:
                calls.append(node)  # type: ignore[arg-type]
                continue
            if kind is ast.Return:
                if node.value is not None:  # type: ignore[attr-defined]
                    returns.append(node)  # type: ignore[arg-type]
                continue
            if kind in (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda):
                self._add_function(node)  # type: ignore[arg-type]
            elif kind is ast.Global or kind is ast.Nonlocal:
                self._escapes.setdefault(id(self.scope_of(node)), set()).update(node.names)  # type: ignore[attr-defined]
            read = readers.get(kind)
            if read is None:
                continue
            if (
                kind is ast.Assign
                and isinstance(node.value, ast.Lambda)  # type: ignore[attr-defined]
                and len(node.targets) == 1  # type: ignore[attr-defined]
                and isinstance(node.targets[0], ast.Name)  # type: ignore[attr-defined]
            ):
                # `recv = lambda n: sock.recv(n)`: a local function by another spelling.
                self._functions.setdefault(node.targets[0].id, []).append(node.value)  # type: ignore[attr-defined]
            scope = self.scope_of(node)
            for targets, value in read(node):
                self._locals.setdefault(id(scope), set()).update(targets)
                self._bindings.append((scope, targets, value))
        self._calls = [call for call in calls if self._callees(call)]
        self._returns: list[tuple[Function, ast.AST]] = [
            (function, function.body)
            for functions in self._functions.values()
            for function in functions
            if isinstance(function, ast.Lambda)
        ]
        for node in returns:
            scope = self.scope_of(node)
            if isinstance(scope, ast.FunctionDef | ast.AsyncFunctionDef) and node.value is not None:
                self._returns.append((scope, node.value))
        #: The calls that save content to a path: written once, read every round.
        saving = (
            *DownloadedPaths.RETRIEVES, *DownloadedPaths.WRITES, *DownloadedPaths.DUMPS,
            "write", "writelines",
        )  # fmt: skip
        self._writers = [
            call
            for call in calls
            if (isinstance(call.func, ast.Name) and call.func.id in DownloadedPaths.RETRIEVES)
            or (isinstance(call.func, ast.Attribute) and call.func.attr in saving)
        ]

    def _add_function(self, node: Function) -> None:
        args = node.args
        self._locals.setdefault(id(node), set()).update(
            x.arg
            for x in (*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg)
            if x is not None
        )
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            self._functions.setdefault(node.name, []).append(node)
            if isinstance(self._parents.get(id(node)), ast.ClassDef) and not any(
                isinstance(d, ast.Name) and d.id == "staticmethod" for d in node.decorator_list
            ):
                self._methods.add(id(node))

    # -- scopes -----------------------------------------------------------------------------------

    def scope_of(self, node: ast.AST) -> ast.AST:
        """The function (or the module) whose variables a name at `node` is looked up in."""
        known = self._scope_cache.get(id(node))
        if known is not None:
            return known
        parent = self._parents.get(id(node))
        while parent is not None and not isinstance(parent, self.FUNCTION):
            parent = self._parents.get(id(parent))
        scope = parent if parent is not None else self._tree
        self._scope_cache[id(node)] = scope
        return scope

    def _owner(self, scope: ast.AST, name: str) -> int:
        """id of the scope a name read or bound in `scope` belongs to."""
        cached = self._owner_cache.get((id(scope), name))
        if cached is None:
            cached = self._owner_cache[(id(scope), name)] = self._find_owner(scope, name)
        return cached

    def _find_owner(self, scope: ast.AST, name: str) -> int:
        node: ast.AST | None = scope
        while node is not None and node is not self._tree:
            if name in self._locals.get(id(node), ()) and name not in self._escapes.get(
                id(node), ()
            ):
                return id(node)
            node = self.scope_of(node) if self._parents.get(id(node)) is not None else None
        return id(self._tree)

    def _key(self, name: ast.Name) -> tuple[int, str]:
        key = self._key_cache.get(id(name))
        if key is None:
            key = self._key_cache[id(name)] = (self._owner(self.scope_of(name), name.id), name.id)
        return key

    def mark(self, names: Iterable[ast.Name]) -> bool:
        """Mark these names sourced, each in its own scope: a value a caller knows was put into
        them though no binding shows it (`shutil.copy(src, dst)` fills `dst`). True when any was
        new; `spread` again to carry them on."""
        before = len(self._marked)
        self._marked.update(self._key(name) for name in names)
        return len(self._marked) != before

    def _callees(self, call: ast.Call) -> list[Function]:
        """The local functions a call can reach: by name, or a method called on `self`/`cls`."""
        func = call.func
        if isinstance(func, ast.Name):
            return self._functions.get(func.id, [])
        if (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id in ("self", "cls")
        ):
            return [f for f in self._functions.get(func.attr, []) if id(f) in self._methods]
        return []

    # -- what a part of an expression carries -----------------------------------------------------

    def carries(self, part: ast.AST) -> bool | None:
        """True when this part is sourced, False when it certainly is not (a name, or a field of a
        keyed dict), None when its parts decide: a name holding a sourced value (a keyed dict used
        whole counts when any key is sourced), a field of one, a call to a local function
        returning one, or a read of a downloaded path."""
        if not (
            self._marked or self._keyed or self._returning or self._returning_keys or self._dl.paths
        ):
            return False if isinstance(part, ast.Name) else None
        if isinstance(part, ast.Name):
            key = self._key(part)
            return key in self._marked or bool(self._keyed.get(key))
        field = self._field(part)
        if field is not None:
            keys = self._keys_of(field[0])
            if keys is not None:
                return field[1] in keys
        if isinstance(part, ast.Call):
            if any(
                id(f) in self._returning or self._returning_keys.get(id(f))
                for f in self._callees(part)
            ):
                return True
            if self._dl.reads(part):
                return True
        return None

    @staticmethod
    def _field(part: ast.AST) -> tuple[ast.AST, str] | None:
        """(the dict, the key) of `d["k"]` or `d.get("k", ...)`."""
        if (
            isinstance(part, ast.Subscript)
            and isinstance(part.slice, ast.Constant)
            and isinstance(part.slice.value, str)
        ):
            return part.value, part.slice.value
        if (
            isinstance(part, ast.Call)
            and isinstance(part.func, ast.Attribute)
            and part.func.attr == "get"
            and part.args
            and isinstance(part.args[0], ast.Constant)
            and isinstance(part.args[0].value, str)
        ):
            return part.func.value, part.args[0].value
        return None

    def _keys_of(self, base: ast.AST) -> set[str] | None:
        """The sourced keys of a keyed dict: a name bound to one and never to a sourced whole, or
        a call to a local function returning one; None when the base is not keyed."""
        if isinstance(base, ast.Name):
            key = self._key(base)
            if key in self._marked or key not in self._keyed:
                return None
            return self._keyed[key]
        if isinstance(base, ast.Call):
            callees = self._callees(base)
            if callees and not any(id(f) in self._returning for f in callees):
                keyed = [self._returning_keys.get(id(f)) for f in callees]
                if any(k is not None for k in keyed):
                    return set().union(*(k for k in keyed if k is not None))
        return None

    def _keys_bound(self, value: ast.AST, sourced: Callable[[ast.AST], bool]) -> set[str] | None:
        """The sourced keys of a value that is a keyed dict, None when it is not one."""
        if isinstance(value, ast.Dict) and all(
            isinstance(k, ast.Constant) and isinstance(k.value, str) for k in value.keys
        ):
            return {
                k.value
                for k, v in zip(value.keys, value.values, strict=True)
                if isinstance(k, ast.Constant) and isinstance(k.value, str) and sourced(v)
            }
        if isinstance(value, ast.Name | ast.Call):
            return self._keys_of(value)
        return None

    def values_of(self, name: ast.Name, depth: int = 0) -> list[ast.AST]:
        """Every value the variable this name reads is bound from; for a parameter of a local
        function that is never rebound, the arguments its callers pass."""
        key = self._key(name)
        values = [
            value
            for scope, targets, value in self._bindings
            if name.id in targets and self._owner(scope, name.id) == key[0]
        ]
        if values or depth > 2:
            return values
        function = next((f for fs in self._functions.values() for f in fs if id(f) == key[0]), None)
        if function is None:
            return []
        out: list[ast.AST] = []
        for call in self._calls:
            if function in self._callees(call):
                out += [v for n, v in self._pairs(call, function) if n == name.id]
        return out

    def is_argument_list(self, command: ast.AST) -> bool:
        """Whether a command is an argument list: written in place, bound to the name it is run by
        (`cmd = [cli, "create", path]; run(cmd)`), chosen by a conditional, or handed in by every
        caller of the function it is a parameter of -- every value it can hold a list or tuple."""
        found = False
        pending: list[tuple[ast.AST, int]] = [(command, 0)]
        while pending:
            value, depth = pending.pop()
            step = self.LIST_STEPS.get(type(value))
            more = step(self, value, depth) if step is not None else None
            if more is None:
                return False
            found = found or not more
            pending += more
        return found

    def _list_leaf(self, value: ast.AST, depth: int) -> list[tuple[ast.AST, int]] | None:
        return []

    def _list_choice(self, value: ast.AST, depth: int) -> list[tuple[ast.AST, int]] | None:
        assert isinstance(value, ast.IfExp)  # noqa: S101 -- dispatched by type
        return [(value.body, depth), (value.orelse, depth)]

    def _list_name(self, value: ast.AST, depth: int) -> list[tuple[ast.AST, int]] | None:
        assert isinstance(value, ast.Name)  # noqa: S101 -- dispatched by type
        found = self.values_of(value) if depth < 3 else []
        return [(v, depth + 1) for v in found] or None

    LIST_STEPS: ClassVar[
        dict[type, Callable[[ScopedTaint, ast.AST, int], list[tuple[ast.AST, int]] | None]]
    ] = {}

    # -- spreading ----------------------------------------------------------------------------------

    def spread(self, sourced: Callable[[ast.AST], bool], rounds: int = ROUNDS) -> ScopedTaint:
        """Mark every name bound from a value `sourced` accepts (`sourced` reads `carries`), every
        downloaded path, through assignments, returns and the arguments of local calls.

        A worklist: the first round reads every binding, return and local call; each later round
        reads only those that mention a name marked (or a function found returning a sourced value)
        in the round before -- nothing else can have changed. A new downloaded path reads everything
        again, since a read of it need not name it."""
        handles = self._dl.handles() if self._writers else {}
        bindings = [
            ([(self._owner(scope, t), t) for t in targets], value, self._mentions(value))
            for scope, targets, value in self._bindings
            if targets
        ]
        returns = [(f, v, self._mentions(v)) for f, v in self._returns]
        calls = [(c, self._mentions(c)) for c in self._calls]
        changed: set[str] | None = None  # None: read everything
        for _ in range(rounds):
            before = self._size()
            paths_before = len(self._dl.paths)
            touched: set[str] = set()
            for keys_of_targets, value, mentions in bindings:
                if changed is not None and changed.isdisjoint(mentions):
                    continue
                if all(k in self._marked for k in keys_of_targets):
                    continue  # settled: a whole mark is the most a binding can give
                keys = self._keys_bound(value, sourced)
                if keys is not None:
                    for k in keys_of_targets:
                        held = self._keyed.setdefault(k, set())
                        if not keys <= held:
                            held.update(keys)
                            touched.add(k[1])
                elif sourced(value):
                    self._marked.update(keys_of_targets)
                    touched.update(k[1] for k in keys_of_targets)
                if self._dl.downloaded(value):
                    self._dl.paths.update(keys_of_targets)
            for function, value, mentions in returns:
                if id(function) in self._returning:
                    continue
                if changed is not None and changed.isdisjoint(mentions):
                    continue
                keys = self._keys_bound(value, sourced)
                if keys is not None:
                    held = self._returning_keys.setdefault(id(function), set())
                    if not keys <= held:
                        held.update(keys)
                        touched |= self._names_of(function)
                elif sourced(value):
                    self._returning.add(id(function))
                    touched |= self._names_of(function)
            for call, mentions in calls:
                if changed is None or not changed.isdisjoint(mentions):
                    touched |= self._across(call, sourced)
            self._dl.saved(sourced, handles)
            if self._size() == before:
                break
            changed = None if len(self._dl.paths) != paths_before else touched
        return self

    def _mentions(self, expr: ast.AST) -> frozenset[str]:
        """Every name and attribute an expression reads: what a change must touch to matter."""
        known = self._mention_cache.get(id(expr))
        if known is None:
            names: set[str] = set()
            for part in ast.walk(expr):
                if isinstance(part, ast.Name):
                    names.add(part.id)
                elif isinstance(part, ast.Attribute):
                    names.add(part.attr)
            known = self._mention_cache[id(expr)] = frozenset(names)
        return known

    def _names_of(self, function: Function) -> set[str]:
        """The names a function is called by: its own, or the name a lambda is assigned to."""
        return {name for name, fs in self._functions.items() if any(f is function for f in fs)}

    def _size(self) -> int:
        return (
            len(self._marked)
            + len(self._returning)
            + len(self._dl.paths)
            + sum(len(k) + 1 for k in self._keyed.values())
            + sum(len(k) + 1 for k in self._returning_keys.values())
        )

    def _pairs(self, call: ast.Call, function: Function) -> list[tuple[str, ast.AST]]:
        """(parameter, argument) for each argument the call passes the function."""
        args = function.args
        positional = [x.arg for x in (*args.posonlyargs, *args.args)]
        if id(function) in self._methods and positional:
            positional = positional[1:]
        pairs: list[tuple[str, ast.AST]] = []
        for index, argument in enumerate(call.args):
            if isinstance(argument, ast.Starred) or index >= len(positional):
                if args.vararg is not None:
                    pairs.append((args.vararg.arg, argument))
            else:
                pairs.append((positional[index], argument))
        for keyword in call.keywords:
            name = keyword.arg
            if name is None or name not in self._locals.get(id(function), ()):
                name = args.kwarg.arg if args.kwarg is not None else None
            if name is not None:
                pairs.append((name, keyword.value))
        return pairs

    def _across(self, call: ast.Call, sourced: Callable[[ast.AST], bool]) -> set[str]:
        """Values into parameters; downloaded paths into parameters, and back out to the argument a
        caller named when the callee wrote to its parameter. Returns the parameters newly marked."""
        touched: set[str] = set()
        for function in self._callees(call):
            for name, value in self._pairs(call, function):
                if (id(function), name) not in self._marked and sourced(value):
                    self._marked.add((id(function), name))
                    touched.add(name)
                if self._dl.downloaded(value):
                    self._dl.paths.add((id(function), name))
                elif (id(function), name) in self._dl.paths:
                    self._dl.mark(value)
        return touched


ScopedTaint.LIST_STEPS.update(
    {
        ast.List: ScopedTaint._list_leaf,
        ast.Tuple: ScopedTaint._list_leaf,
        ast.IfExp: ScopedTaint._list_choice,
        ast.Name: ScopedTaint._list_name,
    }
)


class DownloadedPaths:
    """The paths a file writes fetched content to, and the reads of them: a ScopedTaint's file
    flow. `fetch(url, CONFIG)` writes the response to CONFIG, `load(CONFIG)` reads it back."""

    #: Calls that read a file's content from the path they are given or called on.
    READS: ClassVar[frozenset[str]] = frozenset({"read_text", "read_bytes"})
    #: Calls that write content to the path they are called on (`Path.write_text(content)`).
    WRITES: ClassVar[frozenset[str]] = frozenset({"write_text", "write_bytes"})
    #: Calls that write their first argument into the handle that is their second.
    DUMPS: ClassVar[frozenset[str]] = frozenset({"dump", "safe_dump", "copyfileobj"})
    #: Calls that save a download to the path they are given second (`urlretrieve(url, path)`).
    RETRIEVES: ClassVar[frozenset[str]] = frozenset({"urlretrieve", "download_file", "wget"})

    def __init__(self, taint: ScopedTaint) -> None:
        self.taint = taint
        self.paths: set[tuple[int, str]] = set()

    def downloaded(self, expr: ast.AST) -> bool:
        if not self.paths:
            return False
        return any(
            isinstance(part, ast.Name) and self.taint._key(part) in self.paths
            for part in PythonSyntax.within(expr, ast.Name)
        )

    #: Modules whose `open(path, mode)` takes the path first, as the builtin does.
    OPENERS: ClassVar[frozenset[str]] = frozenset({"io", "codecs", "os", "gzip", "bz2", "lzma"})

    @classmethod
    def opened(cls, call: ast.Call) -> tuple[ast.AST, bool] | None:
        """(the path, whether the mode writes) of an `open` call: `open(path, mode)`,
        `io.open(path, mode)`, or `path.open(mode)`."""
        func = call.func
        if isinstance(func, ast.Name) and func.id == "open" and call.args:
            path, mode_index = call.args[0], 1
        elif isinstance(func, ast.Attribute) and func.attr == "open":
            if isinstance(func.value, ast.Name) and func.value.id in cls.OPENERS:
                if not call.args:
                    return None
                path, mode_index = call.args[0], 1
            else:
                path, mode_index = func.value, 0
        else:
            return None
        mode: ast.AST | None = call.args[mode_index] if len(call.args) > mode_index else None
        for keyword in call.keywords:
            if keyword.arg == "mode":
                mode = keyword.value
        writes = (
            isinstance(mode, ast.Constant)
            and isinstance(mode.value, str)
            and any(c in mode.value for c in "wax+")
        )
        return path, writes

    def reads(self, call: ast.Call) -> bool:
        """`open(path)` for reading, `path.read_text()`, `path.open()` of a downloaded path."""
        opened = self.opened(call)
        if opened is not None:
            return not opened[1] and self.downloaded(opened[0])
        func = call.func
        return (
            isinstance(func, ast.Attribute)
            and func.attr in self.READS
            and self.downloaded(func.value)
        )

    def handles(self) -> dict[tuple[int, str], ast.AST]:
        """Names bound to a file opened for writing, with the path it was opened at."""
        handles: dict[tuple[int, str], ast.AST] = {}
        for scope, targets, value in self.taint._bindings:
            opened = self.opened(value) if isinstance(value, ast.Call) else None
            if opened is not None and opened[1]:
                for target in targets:
                    handles[(self.taint._owner(scope, target), target)] = opened[0]
        return handles

    def saved(
        self, sourced: Callable[[ast.AST], bool], handles: dict[tuple[int, str], ast.AST]
    ) -> None:
        """Paths sourced content is written to become downloaded paths."""
        for call in self.taint._writers:
            func = call.func
            if not isinstance(func, ast.Attribute):
                if isinstance(func, ast.Name) and func.id in self.RETRIEVES and len(call.args) > 1:
                    self.mark(call.args[1])
                continue
            if func.attr in self.RETRIEVES and len(call.args) > 1:
                self.mark(call.args[1])
            elif func.attr in self.WRITES and call.args and sourced(call.args[0]):
                self.mark(func.value)
            elif func.attr in ("write", "writelines") and call.args and sourced(call.args[0]):
                self._handle(func.value, handles)
            elif func.attr in self.DUMPS and len(call.args) > 1 and sourced(call.args[0]):
                self._handle(call.args[1], handles)

    def _handle(self, handle: ast.AST, handles: dict[tuple[int, str], ast.AST]) -> None:
        if isinstance(handle, ast.Name):
            path = handles.get(self.taint._key(handle))
            if path is not None:
                self.mark(path)

    def mark(self, expr: ast.AST) -> None:
        for part in PythonSyntax.within(expr, ast.Name):
            if isinstance(part, ast.Name):
                self.paths.add(self.taint._key(part))


__all__ = ["BindingForms", "DownloadedPaths", "ScopedTaint"]
