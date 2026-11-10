"""Which files of a published package run when it is used rather than installed.

Moved out of `engine/engine.py` (0.7.0 layout: a long module only shrinks). The engine records
them as `import_entry_paths`, and, without the command targets, as `library_entry_paths`.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.ecosystems.registry import RegistryFacts
from cordon_scanner.foundation.formats.served_json import ServedJson

if TYPE_CHECKING:
    from cordon_scanner.detect.base import FileUnit


class PackageEntries:
    @staticmethod
    def of(units: list[FileUnit], distribution: str, *, with_bin: bool = True) -> frozenset[str]:
        """The files of a published package that run when it is used rather than installed: npm's
        `main` (or `index.js`), `bin` and `exports` targets; a wheel's or sdist's top-level
        `__init__.py`. Their module top level runs on `require()`, `import` or the command, on
        every consumer, with no hook in the manifest (review 98, REC-2)."""
        members: dict[str, str] = {}
        for unit in units:
            _, sep, member = unit.path.partition("!")
            if sep and "!" not in member:
                members[member] = unit.path
        manifest = PackageEntries.manifest(units, distribution)
        return frozenset(RegistryFacts.library_entries(distribution, members, manifest, with_bin))

    @staticmethod
    def importable_modules(units: list[FileUnit], distribution: str) -> frozenset[str]:
        """Every module of a published package a consumer can import as the package, by its
        ecosystem (`import_modules`): their top level runs when imported (reviews/pypi-98/10)."""
        members: dict[str, str] = {}
        for unit in units:
            _, sep, member = unit.path.partition("!")
            if sep and "!" not in member:
                members[member] = unit.path
        return frozenset(RegistryFacts.import_modules(distribution, members))

    PROJECT_SCRIPTS: ClassVar[frozenset[str]] = frozenset(
        f"{when}{name}" for name in ("dev", "build", "start") for when in ("", "pre", "post")
    )
    """The scripts a person runs to use a published project (`npm run dev`, `npm start`), with
    the pre and post scripts npm runs around them. Item 72: 323 of 374 npm malware misses with
    code outside every reach set were app projects whose payload runs on these, not on install;
    the owner's ruling is a strict scanner (3 Nov), so what they run is reached code."""

    TOOL_CONFIG: ClassVar[re.Pattern[str]] = re.compile(r"^[\w.-]+\.config\.[cm]?[jt]s$")
    """A build tool's configuration beside the manifest (`next.config.mjs`, `vite.config.ts`):
    code the tool loads and runs when one of those scripts does. A file-name convention, not a
    list of tools."""

    @staticmethod
    def project_run(units: list[FileUnit], distribution: str) -> frozenset[str]:
        """The files a published package's own dev, build and start scripts run, and the tool
        configurations they load: empty for a package with none of those scripts."""
        from cordon_scanner.engine.pipeline.hooks import Hooks
        from cordon_scanner.foundation.models import Hook

        place = RegistryFacts.archive_manifest(distribution)
        scripts = PackageEntries.manifest(units, distribution).get("scripts")
        if place is None or not isinstance(scripts, dict):
            return frozenset()
        hooks = [
            Hook(kind="build", path=place, name=name, command=command)
            for name, command in scripts.items()
            if name in PackageEntries.PROJECT_SCRIPTS and isinstance(command, str)
        ]
        manifest = next((u.path for u in units if u.path.endswith(f"!{place}")), None)
        if not hooks or manifest is None:
            return frozenset()
        known = frozenset(u.path for u in units)
        found = Hooks.hook_script_paths(manifest, hooks, known)
        here = manifest.rpartition("/")[0]
        found.update(
            u.path
            for u in units
            if u.path.rpartition("/")[0] == here
            and PackageEntries.TOOL_CONFIG.match(u.path.rpartition("/")[2])
        )
        return frozenset(found)

    @staticmethod
    def manifest(units: list[FileUnit], distribution: str) -> dict[str, Any]:
        """The published archive's own manifest where its ecosystem fixes the place
        (`archive_manifest`), as a JSON object; {} where there is none or it does not read."""
        place = RegistryFacts.archive_manifest(distribution)
        if place is None:
            return {}
        manifest = next((u for u in units if u.path.endswith(f"!{place}")), None)
        try:
            document = (
                ServedJson.loads(manifest.content.text, manifest.path)
                if manifest is not None
                else {}
            )
        except (ValueError, RecursionError):
            return {}
        return document if isinstance(document, dict) else {}

    @staticmethod
    def repository(units: list[FileUnit], distribution: str) -> str:
        """The published package's own `repository` URL, or "": a string, or an object's `url`, as
        its manifest declares it (review 98, FP-2)."""
        return RegistryFacts.published_repository(
            distribution, PackageEntries.manifest(units, distribution)
        )


class PythonScripts:
    """The modules a Python package's commands run (`console_scripts`, `gui_scripts`, a Poetry
    `scripts` table): `pkg-run = pkg.cli:main` runs pkg/cli.py's top level on every invocation,
    whether or not `__init__` imports it (S2, lead 2026-11-10: a payload in syntax newer than the
    scanner's Python, placed only in the command's module, ran unread). Read from every place a
    distribution declares them: a wheel's or egg-info's entry_points.txt, pyproject.toml,
    setup.cfg, and a literal `entry_points=` in setup.py."""

    GROUPS: ClassVar[tuple[str, ...]] = ("console_scripts", "gui_scripts")
    #: A setup.py whose `entry_points=` or `scripts=` is not a literal: its commands could name
    #: any module, test files included, so every `.py` of that archive is running for the
    #: unparsed check (fail closed; lead, 2026-11-10).
    UNKNOWN: ClassVar[str] = "*"

    @staticmethod
    def targets(units: list[FileUnit]) -> frozenset[str]:
        """Unit paths of the `.py` files the declared commands name, within each archive."""
        modules: set[tuple[str, str]] = set()  # (archive prefix, dotted module)
        for unit in units:
            archive, sep, member = unit.path.rpartition("!")
            if not sep:
                continue
            name = member.rsplit("/", 1)[-1]
            text = unit.content.text if not unit.content.is_binary else ""
            for target in PythonScripts._declared(name, text):
                modules.add((archive, target.split(":", 1)[0].strip()))
        unknown = {archive for archive, module in modules if module == PythonScripts.UNKNOWN}
        found: set[str] = set()
        for unit in units:
            archive, sep, member = unit.path.rpartition("!")
            if not sep or not member.endswith(".py"):
                continue
            if archive in unknown:
                found.add(unit.path)
                continue
            for owner, module in modules:
                if owner != archive or not module:
                    continue
                stem = module.replace(".", "/")
                if ("/" + member).endswith((f"/{stem}.py", f"/{stem}/__init__.py")):
                    found.add(unit.path)
        return frozenset(found)

    @staticmethod
    def _declared(name: str, text: str) -> list[str]:
        """`module:function` targets a file declares, by the file's own format; [] if none."""
        if name == "entry_points.txt" or name == "setup.cfg":
            return PythonScripts._ini(text, name == "setup.cfg")
        if name == "pyproject.toml":
            return PythonScripts._pyproject(text)
        if name == "setup.py":
            return PythonScripts._setup_py(text)
        return []

    @staticmethod
    def _ini(text: str, setup_cfg: bool) -> list[str]:
        import configparser

        parser = configparser.ConfigParser(interpolation=None)
        try:
            parser.read_string(text)
        except (configparser.Error, ValueError):
            return []
        out: list[str] = []
        if setup_cfg:
            if parser.has_section("options.entry_points"):
                for group in PythonScripts.GROUPS:
                    value = parser.get("options.entry_points", group, fallback="")
                    out += [ln.split("=", 1)[1] for ln in value.splitlines() if "=" in ln]
            return out
        for group in PythonScripts.GROUPS:
            if parser.has_section(group):
                out += [v for _, v in parser.items(group)]
        return out

    @staticmethod
    def _pyproject(text: str) -> list[str]:
        import tomllib

        try:
            document = tomllib.loads(text)
        except (tomllib.TOMLDecodeError, ValueError, RecursionError):
            return []
        project = document.get("project", {})
        tables = [
            project.get("scripts", {}),
            project.get("gui-scripts", {}),
            document.get("tool", {}).get("poetry", {}).get("scripts", {}),
        ]
        return [v for t in tables if isinstance(t, dict) for v in t.values() if isinstance(v, str)]

    @staticmethod
    def _setup_py(text: str) -> list[str]:
        import ast

        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            return []  # S2: covered: a setup.py that does not parse is MANIFEST.UNPARSED
        out: list[str] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.keyword) or node.arg not in ("entry_points", "scripts"):
                continue
            if node.arg == "scripts":
                # Script files by path; built at run time, they could be any file (fail closed).
                try:
                    ast.literal_eval(node.value)
                except (ValueError, SyntaxError, TypeError, RecursionError, MemoryError):
                    # S2: recorded as UNKNOWN: scripts built at run time could name any module.
                    return [PythonScripts.UNKNOWN]
                continue
            try:
                value = ast.literal_eval(node.value)
            except (ValueError, SyntaxError, TypeError, RecursionError, MemoryError):
                # S2: recorded as UNKNOWN: commands built at run time could name any module.
                return [PythonScripts.UNKNOWN]
            if not isinstance(value, dict):
                return [PythonScripts.UNKNOWN]
            for group in PythonScripts.GROUPS:
                lines = value.get(group, [])
                lines = [lines] if isinstance(lines, str) else lines
                out += [ln.split("=", 1)[1] for ln in lines if isinstance(ln, str) and "=" in ln]
        return out


__all__ = ["PackageEntries", "PythonScripts"]
