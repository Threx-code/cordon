"""Which files run when a package is used rather than installed, and which files a tree itself names as the code that runs.

Moved out of `engine/engine.py` (0.7.0 layout: a long module only shrinks). The engine records
them as `import_entry_paths`, and, without the command targets, as `library_entry_paths`.
`DeclaredEntries` is the other reading: the files a manifest of a cloned repository names (package.json, pyproject, an MCP
configuration, a Dockerfile), where a repository has for its places every file that could be an entry.
"""

from __future__ import annotations

import json
import posixpath
import re
import tomllib
from typing import TYPE_CHECKING, Any, ClassVar, Final

from cordon_scanner.ecosystems.registry import RegistryFacts
from cordon_scanner.foundation.formats.served_json import ServedJson

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from cordon_scanner.detect.base import FileUnit

MAX_MANIFEST: Final = 1_000_000


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
    def version(units: list[FileUnit], distribution: str) -> str:
        """The version the published package declares, or "": its manifest's `version` where the
        ecosystem keeps one, else the `Version:` header of the core-metadata file at the archive's
        top (the file that opens with `Metadata-Version:`)."""
        value = PackageEntries.manifest(units, distribution).get("version")
        if isinstance(value, str):
            return value
        for unit in units:
            member = unit.path.rsplit("!", 1)[-1]
            if member.count("/") != 1 or unit.content.is_binary:
                continue
            head = unit.content.text_head(8_192)
            if head.startswith("Metadata-Version:"):
                found = re.search(r"(?m)^Version:[ \t]*(\S{1,64})", head)
                if found:
                    return found.group(1)
        return ""

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

        from cordon_scanner.analysis.python.pysyntax import PythonSyntax

        try:
            tree = PythonSyntax.parse(text)  # the guarded parse (test_untrusted_parse.py)
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


class DeclaredEntries:
    """`of(units)`: the paths of the units a manifest of the tree names as an entry."""

    #: A file name a command or an argument runs.
    SOURCE: ClassVar[re.Pattern[str]] = re.compile(
        r"[\w@.+/\\-]{1,200}\.(?:c?js|mjs|jsx|tsx?|py|sh|bash)\b"
    )
    CONFIGS: ClassVar[tuple[str, ...]] = (
        "mcp.json",
        ".mcp.json",
        "claude_desktop_config.json",
        "mcp_config.json",
        "cline_mcp_settings.json",
        "settings.json",
        "settings.local.json",
    )
    _ENTRY_LINE: ClassVar[re.Pattern[str]] = re.compile(r"(?im)^\s*(?:ENTRYPOINT|CMD)\b(.*)$")
    _SETUP_ENTRY: ClassVar[re.Pattern[str]] = re.compile(
        r"""['"][\w.-]{1,80}\s*=\s*([\w.]{1,200}):[\w.]{1,100}['"]"""
    )

    @classmethod
    def of(cls, units: Sequence[FileUnit]) -> frozenset[str]:
        paths = {unit.path for unit in units}
        named: set[str] = set()
        for unit in units:
            if "node_modules/" in unit.path or "!" in unit.path:
                continue
            name = unit.path.rpartition("/")[2]
            base = unit.path.rpartition("/")[0]
            try:
                text = unit.content.raw[:MAX_MANIFEST].decode("utf-8", "replace")
            except AttributeError:
                continue
            found = cls._named_by(name, text)
            if found is None:
                continue
            files, modules = found
            roots = (
                ("", base)
                if name in cls.CONFIGS or name.lower().startswith("dockerfile")
                else (base,)
            )
            for token in files:
                named.update(
                    candidate for root in roots if (candidate := cls._join(root, token)) in paths
                )
            for module in modules:
                named.update(
                    candidate for candidate in cls._module_files(base, module) if candidate in paths
                )
        return frozenset(named)

    @classmethod
    def _named_by(cls, name: str, text: str) -> tuple[list[str], list[str]] | None:
        """(file names, module names) a manifest, a configuration or a Dockerfile names, or None for any other file."""
        lowered = name.lower()
        if name == "package.json":
            return cls._package_json(text), []
        if name == "pyproject.toml":
            return [], cls._pyproject(text)
        if name == "setup.py":
            return [], cls._SETUP_ENTRY.findall(text)
        if name in cls.CONFIGS:
            return cls._configuration(text), []
        if (
            lowered == "dockerfile"
            or lowered.startswith("dockerfile.")
            or lowered.endswith(".dockerfile")
        ):
            return [
                token
                for line in cls._ENTRY_LINE.findall(text)
                for token in cls.SOURCE.findall(line)
            ], []
        return None

    @classmethod
    def _package_json(cls, text: str) -> list[str]:
        try:
            data = json.loads(text)
        except ValueError:
            return []
        if not isinstance(data, dict):
            return []
        names: list[str] = []
        for key in ("main", "module", "browser"):
            if isinstance(data.get(key), str):
                names.append(data[key])
        bin_ = data.get("bin")
        names += (
            [bin_]
            if isinstance(bin_, str)
            else list(bin_.values())
            if isinstance(bin_, dict)
            else []
        )
        names += cls._strings(data.get("exports"))
        scripts = data.get("scripts")
        if isinstance(scripts, dict):
            for command in scripts.values():
                if isinstance(command, str):
                    names += cls.SOURCE.findall(command)
        return [name for name in names if isinstance(name, str)]

    @classmethod
    def _strings(cls, value: Any) -> list[str]:
        if isinstance(value, str):
            return [value]
        if isinstance(value, dict):
            return [s for item in value.values() for s in cls._strings(item)]
        if isinstance(value, list):
            return [s for item in value for s in cls._strings(item)]
        return []

    @classmethod
    def _pyproject(cls, text: str) -> list[str]:
        try:
            data = tomllib.loads(text)
        except (tomllib.TOMLDecodeError, ValueError):
            return []
        tables: list[Any] = [
            data.get("project", {}).get("scripts"),
            data.get("project", {}).get("gui-scripts"),
            data.get("tool", {}).get("poetry", {}).get("scripts"),
            *(data.get("project", {}).get("entry-points", {}) or {}).values(),
        ]
        targets = [
            t
            for table in tables
            if isinstance(table, dict)
            for t in table.values()
            if isinstance(t, str)
        ]
        return [target.split(":", 1)[0].split("[", 1)[0].strip() for target in targets]

    @classmethod
    def _configuration(cls, text: str) -> list[str]:
        try:
            data = json.loads(text)
        except ValueError:
            return []
        found: list[str] = []

        cls._walk(data, found)
        return found

    @classmethod
    def _walk(cls, node: Any, found: list[str]) -> None:
        """Every server entry of a configuration (a dict with a `command`): the files its command and arguments run."""
        if isinstance(node, dict):
            if isinstance(node.get("command"), str):
                found.extend(cls.SOURCE.findall(node["command"]))
                for argument in node.get("args") or []:
                    if isinstance(argument, str):
                        found.extend(cls.SOURCE.findall(argument))
            for value in node.values():
                cls._walk(value, found)
        elif isinstance(node, list):
            for value in node:
                cls._walk(value, found)

    @staticmethod
    def _join(root: str, token: str) -> str:
        token = token.replace("\\", "/").strip().strip("'\"")
        while token.startswith("./"):
            token = token[2:]
        return (
            posixpath.normpath(posixpath.join(root, token))
            if token and not token.startswith("/")
            else ""
        )

    @staticmethod
    def _module_files(base: str, module: str) -> Iterable[str]:
        """The files a dotted module name can be: its file or its package, in the manifest's folder or under `src`."""
        relative = module.strip().replace(".", "/")
        if not relative or not re.fullmatch(r"[\w/]{1,200}", relative):
            return []
        return [
            posixpath.normpath(posixpath.join(base, prefix, relative + suffix))
            for prefix in ("", "src")
            for suffix in (".py", "/__init__.py")
        ]


__all__ = ["DeclaredEntries", "PackageEntries", "PythonScripts"]
