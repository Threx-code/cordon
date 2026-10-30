"""Python source parsed as data.

`ast.parse` warns about the source it reads: `"\\h"`, an invalid escape in a scanned file, is a
`SyntaxWarning` (a `DeprecationWarning` before 3.12), written to the scanner's own stderr once per
literal. Scanning stable-diffusion printed seven of them into a CI log, which reads as the
scanner failing. A scanned file's escapes are its author's business; the warnings are not ours to
print, so every parse of untrusted source goes through here.
"""

from __future__ import annotations

import ast
import bisect
import collections
import functools
import warnings
import weakref
from collections.abc import Callable
from typing import Any, ClassVar

from cordon_scanner.foundation.collector import ScanCaches


class PythonSyntax:
    @staticmethod
    def parse(source: str | bytes, filename: str = "<unknown>", mode: str = "exec") -> Any:
        """`ast.parse`, without the warnings it raises about the source. Raises what it raises:
        a `SyntaxError` (or `ValueError` for a NUL byte) is still the caller's to handle."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            warnings.simplefilter("ignore", DeprecationWarning)
            return ast.parse(source, filename=filename, mode=mode)

    @staticmethod
    @ScanCaches.register  # holds files: emptied after each scan (foundation/collector)
    @functools.lru_cache(maxsize=4)
    def shared(source: str | bytes) -> Any:
        """One parse of `source` shared by every reader that does not change the tree: the Python
        analyser asks four questions of each file, and parsing it four times was most of a large
        package's scan. A reader that annotates or rewrites nodes must call `parse`."""
        tree = PythonSyntax.parse(source)
        TreeIndex.build(tree)
        return tree

    @staticmethod
    def within(node: ast.AST, *types: type) -> list[Any]:
        """The nodes of `types` in `node`'s subtree, `node` included -- what filtering
        `ast.walk(node)` gives, in depth-first rather than breadth-first order.

        For a question about a subtree that order cannot change: "is any Name under here one of
        these", "collect the string literals under here". A reader that takes the first match in
        walk order keeps `nodes`. Answered from the tree's `TreeIndex` by a range lookup, where a
        fresh walk of every subtree asked about was most of the Python analyser's time: 1.7
        million subtree walks over ten thousand files. A node from a tree parsed outside `shared`
        is not indexed and is walked, as before.
        """
        place: tuple[Any, int, int] | None = node.__dict__.get("_cordon_place")
        index: TreeIndex | None = place[0]() if place is not None else None
        if index is None or place is None:
            return [n for n in PythonSyntax.nodes(node) if isinstance(n, types)]
        return index.between(place[1], place[2], types)

    @staticmethod
    def parents(tree: ast.AST) -> dict[int, ast.AST]:
        """`id(node) -> parent` for every node of `tree`: from its `TreeIndex` when it has one, which
        recorded them on its one traversal; built once and kept on the tree otherwise. Four passes
        of the Python analyser each built this map for every file by asking every node for its
        children again -- 3.3 million `iter_child_nodes` calls scanning this package.
        """
        place: tuple[Any, int, int] | None = tree.__dict__.get("_cordon_place")
        index: TreeIndex | None = place[0]() if place is not None else None
        if index is not None and place is not None and place[1] == 0:
            return index.parents

        def compute() -> dict[int, ast.AST]:
            parents: dict[int, ast.AST] = {}
            for node in PythonSyntax.nodes(tree):
                for child in ast.iter_child_nodes(node):
                    parents[id(child)] = node
            return parents

        found: dict[int, ast.AST] = PythonSyntax.memo(tree, "parents", compute)
        return found

    @staticmethod
    def passed(tree: ast.AST) -> list[tuple[ast.AST, int, str]]:
        """`(argument, id(function), parameter)` for each call of a function of this file:
        `beacon(data)` binds `data` to `beacon`'s first parameter, so what the argument carries
        the parameter carries, however many calls deep it is handed on. `self.send(x)` skips
        `self`; a `*args` or keyword-only parameter is not followed."""
        functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {
            f.name: f for f in PythonSyntax.of(tree, ast.FunctionDef, ast.AsyncFunctionDef)
        }
        out: list[tuple[ast.AST, int, str]] = []
        for call in PythonSyntax.of(tree, ast.Call):
            func = call.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
            function = functions.get(name) if isinstance(name, str) else None
            if function is None:
                continue
            params = [a.arg for a in (*function.args.posonlyargs, *function.args.args)]
            if isinstance(func, ast.Attribute) and params[:1] in (["self"], ["cls"]):
                params = params[1:]
            out.extend((arg, id(function), p) for arg, p in zip(call.args, params, strict=False))
            known = set(params)
            out.extend((k.value, id(function), k.arg) for k in call.keywords if k.arg in known)
        return out

    @staticmethod
    def name_scope(tree: ast.AST) -> Callable[[ast.AST, str], int]:
        """Where a name used at `node` is bound, as Python resolves it: the nearest enclosing
        function that binds it (a parameter or an assignment, `global` excepted), else the module
        (0). Returns the binding function's `id`, so a name can be told apart per scope:
        `env = dict(os.environ)` in one function is not the `env` another sends (review 98)."""
        parents = PythonSyntax.parents(tree)
        local: dict[int, set[str]] = {}
        for function in PythonSyntax.of(tree, ast.FunctionDef, ast.AsyncFunctionDef):
            arguments = function.args
            bound = {
                a.arg for a in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs)
            }
            bound |= {a.arg for a in (arguments.vararg, arguments.kwarg) if a is not None}
            bound |= {
                n.id
                for n in PythonSyntax.within(function, ast.Name)
                if isinstance(n.ctx, ast.Store)
                and PythonSyntax.enclosing_function(n, parents) is function
            }
            declared = {g for n in PythonSyntax.within(function, ast.Global) for g in n.names}
            local[id(function)] = bound - declared

        def scope(node: ast.AST, name: str) -> int:
            owner = PythonSyntax.enclosing_function(node, parents)
            while owner is not None and name not in local.get(id(owner), ()):
                owner = PythonSyntax.enclosing_function(owner, parents)
            return 0 if owner is None else id(owner)

        return scope

    @staticmethod
    def enclosing_function(node: ast.AST, parents: dict[int, ast.AST]) -> ast.AST | None:
        """The function whose body `node` is in -- for a function, the one it is nested in -- or
        None at module level. A class body is no scope here: its names fall through to the
        module's, as a method sees them."""
        parent = parents.get(id(node))
        while parent is not None and not isinstance(
            parent, (ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            parent = parents.get(id(parent))
        return parent

    @staticmethod
    def nodes(tree: ast.AST) -> list[ast.AST]:
        """Every node of `tree`, computed once per tree, for a reader that walks it many times: the
        `TreeIndex` order (depth-first) for the root of an indexed tree, else `ast.walk`'s."""
        place: tuple[Any, int, int] | None = tree.__dict__.get("_cordon_place")
        index: TreeIndex | None = place[0]() if place is not None else None
        if index is not None and place is not None and place[1] == 0:
            # The root of an indexed tree: its depth-first order is already built, and a second
            # full traversal for a breadth-first one was most of what the index cost.
            return index.order
        walked: list[ast.AST] = PythonSyntax.memo(tree, "nodes", lambda: list(ast.walk(tree)))
        return walked

    @staticmethod
    def memo(node: ast.AST, key: object, compute: Callable[[], Any]) -> Any:
        """`compute()`, once per node and key: something made of `node`'s subtree -- a list of its
        nodes, its parents' table, an analyser's name tables.

        Kept on the node's `TreeIndex`, under the node's entry number, not on the node: a list of a
        subtree's nodes starts with the subtree's root, so a list kept on the root made the root
        reference itself, every indexed tree was cyclic garbage, and each waited for the cycle
        collector -- 800 MB a window on datadog 16.0.0's generated modules (review 98, D1). Nodes
        reach their index through a weak reference, so the index, its lists and the tree go
        together, by reference counts, once `TreeIndex.RECENT` lets the index go. A node of a tree
        parsed outside `shared` has no index and keeps its lists on itself, as before."""
        place: tuple[Any, int, int] | None = node.__dict__.get("_cordon_place")
        index: TreeIndex | None = place[0]() if place is not None else None
        store: dict[Any, Any] = (
            index.cache if index is not None else node.__dict__.setdefault("_cordon_memo", {})
        )
        slot = (place[1], key) if index is not None and place is not None else key
        found = store.get(slot)
        if found is None:
            found = compute()
            store[slot] = found
        return found

    @staticmethod
    def of(tree: ast.AST, *types: type) -> list[Any]:
        """The nodes of `tree` that are instances of `types`, in `nodes` order, computed once per tree
        and set of types. Most analysis passes want only calls, or only assignments: filtering the
        whole tree inside each of them was most of the Python analyser's time on a large tree --
        76 million `isinstance` calls scanning this package's 239 Python files."""

        def compute() -> list[Any]:
            place: tuple[Any, int, int] | None = tree.__dict__.get("_cordon_place")
            index: TreeIndex | None = place[0]() if place is not None else None
            if index is not None and place is not None and place[1] == 0:
                # The root of an indexed tree: its per-type positions, merged in order, are the same
                # list in the same order as filtering every node, without testing every node.
                return [index.order[p] for p in index.positions(types)]
            return [node for node in PythonSyntax.nodes(tree) if isinstance(node, types)]

        found: list[Any] = PythonSyntax.memo(tree, ("of", types), compute)
        return found


class TreeIndex:
    """One depth-first pass over a tree: every node's entry and exit number, and per node type
    the entry numbers of its nodes, ascending. A subtree is the entry numbers between its root's
    entry and exit, so "nodes of this type under that node" is two binary searches.

    Each node carries `(weak reference to the index, entry, exit)` as `_cordon_place`. Memory is
    linear in the tree: one tuple per node and one list entry per node, where caching every
    subtree's own walk grew with the tree's size times its depth. The index references the nodes
    and nothing references the index but `RECENT`, the last few built: no cycle, so a file's index
    and tree are freed as soon as they leave it. A node whose index is gone is walked instead.
    """

    RECENT: ClassVar[collections.deque[TreeIndex]] = collections.deque(maxlen=8)

    def __init__(self) -> None:
        self.order: list[ast.AST] = []
        self.by_type: dict[type, list[int]] = {}
        self.kinds: dict[tuple[type, ...], list[type]] = {}
        self.parents: dict[int, ast.AST] = {}
        """`id(child) -> parent`, recorded during the same traversal."""
        self.cache: dict[Any, Any] = {}
        """`(entry, key) -> value`: what `PythonSyntax.memo` keeps for this tree's nodes."""

    @staticmethod
    def build(tree: ast.AST) -> TreeIndex:
        index = TreeIndex()
        TreeIndex.RECENT.append(index)
        reference = weakref.ref(index)
        order, by_type = index.order, index.by_type
        stack: list[tuple[ast.AST, int]] = [(tree, -1)]
        while stack:
            node, entered = stack.pop()
            if entered >= 0:
                node.__dict__["_cordon_place"] = (reference, entered, len(order))
                continue
            entry = len(order)
            order.append(node)
            by_type.setdefault(type(node), []).append(entry)
            stack.append((node, entry))
            # `ast.iter_child_nodes`, inlined: the same children in the same order, read from each
            # field directly rather than through two generators per node.
            children: list[ast.AST] = []
            for name in node._fields:
                if name == "ctx":
                    # `Load`, `Store`, `Del`: one shared marker per kind, pushed again under every
                    # name, attribute and subscript -- a third of the traversal. No reader asks the
                    # index for them; `node.ctx` is read directly where it matters.
                    continue
                value = getattr(node, name, None)
                if isinstance(value, ast.AST):
                    children.append(value)
                elif isinstance(value, list):
                    children.extend(item for item in value if isinstance(item, ast.AST))
            parents = index.parents
            for child in children:
                parents[id(child)] = node
            stack.extend((child, -1) for child in reversed(children))
        return index

    def positions(self, types: tuple[type, ...]) -> list[int]:
        """Every position of a node of `types`, ascending: each matching type's list, merged."""
        kinds = self.kinds.get(types)
        if kinds is None:
            kinds = [kind for kind in self.by_type if issubclass(kind, types)]
            self.kinds[types] = kinds
        if len(kinds) == 1:
            return self.by_type[kinds[0]]
        return sorted(p for kind in kinds for p in self.by_type[kind])

    def between(self, entry: int, exit_: int, types: tuple[type, ...]) -> list[Any]:
        """The nodes of `types` whose entry numbers lie in [entry, exit_), each type in order."""
        kinds = self.kinds.get(types)
        if kinds is None:
            kinds = [kind for kind in self.by_type if issubclass(kind, types)]
            self.kinds[types] = kinds
        found: list[Any] = []
        for kind in kinds:
            positions = self.by_type[kind]
            low = bisect.bisect_left(positions, entry)
            high = bisect.bisect_left(positions, exit_)
            found.extend(self.order[p] for p in positions[low:high])
        return found


# The last trees' indexes (and through them the trees), emptied after each scan.
ScanCaches.register(TreeIndex.RECENT)

__all__ = ["PythonSyntax", "TreeIndex"]
