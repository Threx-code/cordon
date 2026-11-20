"""How each code file of a package is reached from a place that runs, for the learning loop's facts (`report/facts.py`, row LL-1c).

A place set (`ScanContext.places`) says where code runs: an install hook, an import entry, an agent's tool handler. Most of a package's
code is in no place set, and the question the loop asks of it is whether anything the package runs reaches it: a spawn and an egress in
a file nothing starts is shipped code, in a file a hook loads it is a program. Each code file is classed, in the order the scanner trusts:

    placed         it is in a place set (an install hook or entry, an import entry, a library entry or closure, an agent tool, a skill's
                   named script, the startup closure, a CI hook): depth 0
    declared_entry the package's package.json names it as its `main`, a `bin` or an `exports` target (a repository has no import-entry set, so
                   this is where its entry is): depth 0
    hook_command   an install hook's command names it (`node scripts/setup.js`, or the script an `npm run` alias runs): depth 0
    require_chain  a static relative require, import or export of a placed or hook-named file, or of a file those reach, names it: the
                   number of hops is the depth (four at most)
    path_string    a string of a root or chain file names it (a joined path, a fork or spawn argument, a computed require): the depth is the
                   mentioning file's plus one
    stem_only      the same with its name's stem only (four letters or more; weaker: `index`-like stems collide)
    unreached      nothing above reaches it: depth 0

The reading is the scanner's own: a JavaScript file is read by the call resolver's parser (`analysis.javascript.front`: `\\uNNNN` escapes are
decoded in a string's value and `"a" + "b"` is folded), a Python file by `ast`. A file past `MAX_PARSE` bytes is a root or a leaf with no
edges of its own (a bundle's requires are node's own). No text of the package leaves this module: it returns paths and classes.
"""

from __future__ import annotations

import ast
import json
import posixpath
import re
from typing import TYPE_CHECKING, ClassVar, Final

from cordon_scanner.analysis.javascript.front.parser import Parser
from cordon_scanner.analysis.javascript.front.syntax import Node, Syntax

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cordon_scanner.detect.base import FileUnit, ScanContext

MAX_DEPTH: Final = 4
#: A file longer than this is not parsed for edges or strings: parsing is the cost, and a bundle's own requires are not the package's.
MAX_PARSE: Final = 2 << 20
_STRING_LIMIT: Final = 300
_HOOKS: Final = ("preinstall", "install", "postinstall", "prepare")
_SEPARATORS: Final = str.maketrans(dict.fromkeys(";&|<>()'\"`=", " "))
_SCRIPT_SUFFIXES: Final = (".js", ".cjs", ".mjs", ".ts", ".py", ".sh")
_ALIAS: Final = re.compile(
    r"(?:npm|pnpm)\s+run(?:-script)?\s+([\w:.-]+)|yarn\s+(?:run\s+)?([\w:.-]+)"
)


class FileReach:
    """Classing every code file of a scanned package by how a place that runs reaches it. Stateless; call `of`."""

    JAVASCRIPT: ClassVar[frozenset[str]] = frozenset(
        {"js", "mjs", "cjs", "jsx", "ts", "tsx", "mts", "cts"}
    )
    CODE: ClassVar[frozenset[str]] = JAVASCRIPT | {
        "py",
        "sh",
        "bash",
        "ps1",
        "rb",
        "php",
        "pl",
        "bat",
        "cmd",
    }
    KINDS: ClassVar[tuple[str, ...]] = (
        "placed",
        "declared_entry",
        "hook_command",
        "require_chain",
        "path_string",
        "stem_only",
        "unreached",
    )
    _RESOLVE: ClassVar[tuple[str, ...]] = (
        "",
        ".js",
        ".cjs",
        ".mjs",
        ".ts",
        ".tsx",
        ".jsx",
        "/index.js",
        "/index.mjs",
        "/index.cjs",
        "/index.ts",
    )

    @staticmethod
    def suffix(path: str) -> str:
        base = path.rpartition("!")[2].rpartition("/")[2]
        return base.rpartition(".")[2].lower() if "." in base else ""

    @staticmethod
    def member(path: str) -> str:
        return path.rpartition("!")[2]

    @classmethod
    def of(cls, units: Sequence[FileUnit], ctx: ScanContext) -> dict[str, tuple[str, int]]:
        """`path -> (kind, depth)` for each code file of the scan (a file of another kind has no entry)."""
        code = {u.path: u for u in units if cls.suffix(u.path) in cls.CODE}
        if not code:
            return {}
        members: dict[str, list[str]] = {}
        for path in code:
            members.setdefault(cls.member(path), []).append(path)
        reach: dict[str, tuple[str, int]] = {}
        depth_of: dict[str, int] = {}
        for attribute in ctx.PLACES.values():
            for path in getattr(ctx, attribute, ()) or ():
                if path in code:
                    reach[path] = ("placed", 0)
                    depth_of[path] = 0
        for kind, found in (
            ("declared_entry", cls.declared_entries(units, members)),
            ("hook_command", cls.hook_files(units, members)),
        ):
            for path in found:
                if path not in reach:
                    reach[path] = (kind, 0)
                    depth_of[path] = 0
        reads: dict[str, _Read] = {}
        frontier = list(depth_of)
        for depth in range(1, MAX_DEPTH + 1):
            nxt: list[str] = []
            for path in frontier:
                for target in cls._read(code[path], reads).edges(members):
                    if target in code and target not in depth_of:
                        depth_of[target] = depth
                        reach[target] = ("require_chain", depth)
                        nxt.append(target)
            frontier = nxt
            if not frontier:
                break
        names: dict[str, int] = {}
        stems: dict[str, int] = {}
        for path, depth in depth_of.items():
            for text in cls._read(code[path], reads).strings:
                base, stem = cls._name(text)
                if base:
                    names[base] = min(names.get(base, depth + 1), depth + 1)
                if stem:
                    stems[stem] = min(stems.get(stem, depth + 1), depth + 1)
        for path in code:
            if path in reach:
                continue
            base = cls.member(path).rpartition("/")[2]
            stem = base.rpartition(".")[0] or base
            if base in names:
                reach[path] = ("path_string", names[base])
            elif len(stem) >= 4 and stem in stems:
                reach[path] = ("stem_only", stems[stem])
            else:
                reach[path] = ("unreached", 0)
        return reach

    @staticmethod
    def _name(text: str) -> tuple[str, str]:
        """The file name and the stem a string names, or empty for each when it names none."""
        text = text.replace("\\", "/").split("?", 1)[0].strip()
        base = text.rpartition("/")[2]
        if not base or len(base) > 120 or " " in base:
            return "", ""
        stem = base.rpartition(".")[0] if "." in base.strip(".") else base
        return (base if "." in base.strip(".") else ""), stem

    @classmethod
    def declared_entries(cls, units: Sequence[FileUnit], members: dict[str, list[str]]) -> set[str]:
        """The files a package.json of the tree names as its `main`, its `bin` or an `exports` target (a name without an extension read as npm
        reads it: `x`, `x.js`, `x/index.js`)."""
        named: set[str] = set()
        for unit in units:
            if unit.path.rpartition("/")[2] != "package.json" or "node_modules/" in unit.path:
                continue
            try:
                data = json.loads(unit.content.raw[:1_000_000].decode("utf-8", "replace"))
            except ValueError:
                continue
            if not isinstance(data, dict):
                continue
            names = [
                *cls._strings(data.get("main")),
                *cls._strings(data.get("bin")),
                *cls._strings(data.get("exports")),
            ]
            folder = cls.member(unit.path).rpartition("/")[0]
            for name in names:
                token = name.replace("\\", "/")
                while token.startswith("./"):
                    token = token[2:]
                base = (
                    posixpath.normpath(posixpath.join(folder, token))
                    if token and not token.startswith("/")
                    else ""
                )
                for candidate in (base, *(base + extra for extra in cls._RESOLVE[1:])):
                    if base and candidate in members:
                        named.update(members[candidate])
                        break
        return named

    @classmethod
    def _strings(cls, value: object) -> list[str]:
        if isinstance(value, str):
            return [value]
        if isinstance(value, dict):
            return [s for item in value.values() for s in cls._strings(item)]
        if isinstance(value, list):
            return [s for item in value for s in cls._strings(item)]
        return []

    @classmethod
    def hook_files(cls, units: Sequence[FileUnit], members: dict[str, list[str]]) -> set[str]:
        """The files an install hook's command names (an `npm run` alias one level down), by every package.json of the tree."""
        named: set[str] = set()
        for unit in units:
            if unit.path.rpartition("/")[2] != "package.json" or "node_modules/" in unit.path:
                continue
            try:
                scripts = json.loads(unit.content.raw[:1_000_000].decode("utf-8", "replace")).get(
                    "scripts"
                )
            except (ValueError, AttributeError):
                continue
            if not isinstance(scripts, dict):
                continue
            commands = [scripts[h] for h in _HOOKS if isinstance(scripts.get(h), str)]
            for command in list(commands):
                for alias in _ALIAS.findall(command):
                    script = scripts.get(alias[0] or alias[1])
                    if isinstance(script, str):
                        commands.append(script)
            folder = cls.member(unit.path).rpartition("/")[0]
            for token in " ".join(commands).translate(_SEPARATORS).split():
                if not token.endswith(_SCRIPT_SUFFIXES) or len(token) > 200:
                    continue
                token = token.replace("\\", "/")
                while token.startswith("./"):
                    token = token[2:]
                for path in members.get(posixpath.normpath(posixpath.join(folder, token)), ()):
                    named.add(path)
        return named

    @classmethod
    def _read(cls, unit: FileUnit, cache: dict[str, _Read]) -> _Read:
        held = cache.get(unit.path)
        if held is None:
            held = cache[unit.path] = _Read(unit, cls)
        return held


class _Read:
    """What one placed or reached file says: the files it loads and the strings it holds (parsed once)."""

    def __init__(self, unit: FileUnit, owner: type[FileReach]) -> None:
        self.unit = unit
        self.owner = owner
        self.specs: list[tuple[str, int]] = []
        self.strings: list[str] = []
        suffix = owner.suffix(unit.path)
        if unit.content.size > MAX_PARSE:
            return
        text = unit.content.text
        if suffix in owner.JAVASCRIPT:
            self._javascript(text, typescript=suffix in {"ts", "tsx", "mts", "cts"})
        elif suffix == "py":
            self._python(text)

    # -- JavaScript: the call resolver's parser ------------------------------------------------------------

    def _javascript(self, text: str, *, typescript: bool) -> None:
        program = Parser(text, typescript=typescript, jsx=not typescript).program()
        for node in Syntax.walk(program):
            kind = node.type
            if kind in (
                "ImportDeclaration",
                "ExportAllDeclaration",
                "ExportNamedDeclaration",
                "ImportExpression",
            ):
                self._spec(node["source"])
            elif kind == "CallExpression":
                callee = node["callee"]
                arguments = node["arguments"] or []
                if (
                    isinstance(callee, Node)
                    and callee.type == "Identifier"
                    and callee["name"] == "require"
                    and arguments
                ):
                    self._spec(arguments[0])
            elif kind == "Literal":
                value = self._string(node)
                if value is not None:
                    self._keep(value)
            elif kind == "BinaryExpression" and node["operator"] == "+":
                folded = self._fold(node)
                if folded is not None:
                    self._keep(folded)

    def _spec(self, node: object) -> None:
        value = self._fold(node) if isinstance(node, Node) else None
        if value is not None and value.startswith("."):
            self.specs.append((value, 0))

    def _keep(self, value: str) -> None:
        if 0 < len(value) <= _STRING_LIMIT:
            self.strings.append(value)

    @staticmethod
    def _string(node: Node) -> str | None:
        if node["kind"] != "string":
            return None
        value = node["value"]
        return value if isinstance(value, str) else None

    @classmethod
    def _fold(cls, node: Node) -> str | None:
        """A string literal's value, or the value of `"a" + "b"` folded; None for anything else."""
        if node.type == "Literal":
            return cls._string(node)
        if node.type == "BinaryExpression" and node["operator"] == "+":
            left, right = node["left"], node["right"]
            if isinstance(left, Node) and isinstance(right, Node):
                a, b = cls._fold(left), cls._fold(right)
                if a is not None and b is not None:
                    return a + b
        return None

    # -- Python: ast ----------------------------------------------------------------------------------------

    def _python(self, text: str) -> None:
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError, RecursionError):
            return
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.specs.append((alias.name, 0))
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                self.specs.append((module, node.level))
                self.specs.extend(
                    ((f"{module}.{alias.name}" if module else alias.name), node.level)
                    for alias in node.names
                )
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                self._keep(node.value)

    # -- the files it loads --------------------------------------------------------------------------------

    def edges(self, members: dict[str, list[str]]) -> list[str]:
        """The files of the tree this file's static requires, imports and exports name (relative JavaScript specs; Python modules)."""
        folder = self.owner.member(self.unit.path).rpartition("/")[0]
        out: list[str] = []
        python = self.owner.suffix(self.unit.path) == "py"
        for spec, level in self.specs:
            if python:
                out.extend(self._python_targets(spec, level, folder, members))
            else:
                target = posixpath.normpath(posixpath.join(folder, spec))
                for candidate in FileReach._RESOLVE:
                    found = members.get(target + candidate)
                    if found:
                        out.extend(found)
                        break
        return out

    @staticmethod
    def _python_targets(
        module: str, level: int, folder: str, members: dict[str, list[str]]
    ) -> list[str]:
        parts = [p for p in module.split(".") if p]
        out: list[str] = []
        if level:
            base = folder
            for _ in range(level - 1):
                base = posixpath.dirname(base)
            relative = posixpath.join(base, *parts) if parts else base
            for candidate in (relative + ".py", relative + "/__init__.py"):
                out.extend(members.get(posixpath.normpath(candidate), ()))
            return out
        tail = "/".join(parts)
        if not tail:
            return out
        for suffix in (tail + ".py", tail + "/__init__.py"):
            for member, paths in members.items():
                if member == suffix or member.endswith("/" + suffix):
                    out.extend(paths)
        return out


__all__ = ["MAX_DEPTH", "FileReach"]
