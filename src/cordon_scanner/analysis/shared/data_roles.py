"""Files that only a data parser ever reads.

A JSON, YAML, TOML or CSV file that the package's code reads with a parser and does nothing else with is
data: the strings in it are values the program looks up, not acts the file performs. The capability rules
read text for the names of things (a credential store's path, a paste service's host), and a data file
that lists them -- a denylist, a table of known hosts, a fixture -- named a drop point and a credential
store in a 48 MB JSON of an MCP server, and was a `HIGH` finding of its own.

The test is the code's, not the path's. A file is data here when

* it has a data format's name (`.json`, `.jsonl`, `.yaml`, `.yml`, `.toml`, `.csv`, `.tsv`, optionally
  compressed) and is not a manifest or a settings file that a rule pack reads for what it declares;
* a code file of the tree (Python, JavaScript, TypeScript) names it, by a literal that ends with its name;
* every such naming sits next to a parser call (`json.load`, `yaml.safe_load`, `csv.reader`,
  `JSON.parse`, `pd.read_csv`, ...) and next to no call that runs, compiles, imports or spawns -- or is the
  assignment of a name whose every other use is such a naming;
* the name picks out one file of the tree: two files of the same name, and the naming is no proof of
  either.

Fail-closed in each direction: a file nothing names, one named without a parser beside it, one named
beside `exec`, `eval`, `subprocess` or a loader, one named by a computed path -- all stay what they were,
read by every rule. A payload in a data file has to be run by something, and what runs it is code that
this test refuses to call a parser. What the exemption removes are the capability rules and the code
model on the file itself (`CapabilityDetector.labelled`); the agent, manifest and instruction rules read
it as before.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import TYPE_CHECKING, ClassVar, Final, Protocol

if TYPE_CHECKING:
    from collections.abc import Sequence

MAX_CODE_BYTES: Final = 2_000_000
#: Lines either side of a naming that count as beside it.
BESIDE: Final = 3


class _Content(Protocol):
    @property
    def text(self) -> str: ...

    @property
    def is_binary(self) -> bool: ...


class _Unit(Protocol):
    """What the test reads of a scanned file: its path and its content (`detect.base.FileUnit`)."""

    @property
    def path(self) -> str: ...

    @property
    def content(self) -> _Content: ...


class DataRoles:
    """`only_parsed(units)`: the paths of the data files the tree's code only ever parses."""

    SUFFIXES: ClassVar[tuple[str, ...]] = (
        ".json",
        ".jsonl",
        ".ndjson",
        ".yaml",
        ".yml",
        ".toml",
        ".csv",
        ".tsv",
    )
    PACKED: ClassVar[tuple[str, ...]] = (".gz", ".bz2", ".xz", ".zst")
    CODE: ClassVar[tuple[str, ...]] = (
        ".py",
        ".pyw",
        ".js",
        ".mjs",
        ".cjs",
        ".jsx",
        ".ts",
        ".tsx",
        ".mts",
        ".cts",
    )
    #: Files a rule pack reads for what they declare: the data test is not made for them.
    DECLARING: ClassVar[tuple[str, ...]] = (
        "package.json",
        "package-lock.json",
        "composer.json",
        "manifest.json",
        "settings.json",
        "settings.local.json",
        "mcp.json",
        "plugin.json",
        "server.json",
        "tsconfig.json",
        "pyproject.toml",
        "cargo.toml",
    )
    #: Calls that read a document's structure and run nothing of it.
    PARSERS: ClassVar[frozenset[str]] = frozenset(
        {
            "json.load",
            "json.loads",
            "orjson.loads",
            "ujson.load",
            "ujson.loads",
            "simplejson.load",
            "simplejson.loads",
            "yaml.safe_load",
            "yaml.safe_load_all",
            "yaml.load",
            "yaml.full_load",
            "tomllib.load",
            "tomllib.loads",
            "toml.load",
            "toml.loads",
            "csv.reader",
            "csv.DictReader",
            "pd.read_json",
            "pd.read_csv",
            "pandas.read_json",
            "pandas.read_csv",
            "JSON.parse",
            "YAML.parse",
            "yaml.parse",
            "jsyaml.load",
            "TOML.parse",
            "toml.parse",
            "Papa.parse",
        }
    )
    #: Names (the last part of a call) that run, compile, load or start what they are given.
    RUNNERS: ClassVar[frozenset[str]] = frozenset(
        {
            "exec",
            "eval",
            "compile",
            "Function",
            "execSync",
            "execFile",
            "execFileSync",
            "spawn",
            "spawnSync",
            "fork",
            "system",
            "popen",
            "Popen",
            "exec_module",
            "import_module",
            "__import__",
            "load_source",
            "spec_from_file_location",
            "runInContext",
            "runInNewContext",
            "runInThisContext",
            "loads_code",
        }
    )
    #: One pass over a text for the suffix of any data file name (the lines that need a closer look).
    _SUFFIX_NAMED: ClassVar[re.Pattern[str]] = re.compile(
        r"\.(?:jsonl?|ndjson|ya?ml|toml|[ct]sv)", re.I
    )
    _ASSIGNED: ClassVar[re.Pattern[str]] = re.compile(
        r"^\s*(?:export\s+)?(?:const\s+|let\s+|var\s+)?([A-Za-z_$][\w$]*)\s*(?::[^=]{1,60})?=[^=]"
    )

    @classmethod
    def only_parsed(cls, units: Sequence[_Unit]) -> frozenset[str]:
        """The paths of the data files in `units` that the code of `units` names only beside a parser."""
        data: dict[str, list[str]] = defaultdict(list)
        for unit in units:
            if cls._is_data(unit):
                data[cls._bare(unit.path.rsplit("/", 1)[-1])].append(unit.path)
        if not data:
            return frozenset()
        verdicts: dict[str, list[bool]] = defaultdict(list)
        for unit in units:
            if not unit.path.lower().endswith(cls.CODE) or unit.content.is_binary:
                continue
            text = unit.content.text
            if len(text) > MAX_CODE_BYTES or cls._SUFFIX_NAMED.search(text) is None:
                continue
            lines = text.split("\n")
            for number, line in enumerate(lines):
                if cls._SUFFIX_NAMED.search(line) is None:
                    continue
                for value in cls._literals(line):
                    named = cls._named(value, data)
                    if named is None:
                        continue
                    verdicts[named].append(cls._beside_a_parser(lines, number))
        return frozenset(p for p, seen in verdicts.items() if seen and all(seen))

    # -- which files --------------------------------------------------------------------------

    @classmethod
    def _is_data(cls, unit: _Unit) -> bool:
        path = unit.path.lower()
        for packed in cls.PACKED:
            if path.endswith(packed):
                path = path[: -len(packed)]
                break
        base = path.rsplit("/", 1)[-1]
        return path.endswith(cls.SUFFIXES) and base not in cls.DECLARING

    @classmethod
    def _bare(cls, name: str) -> str:
        """A file name without a compression suffix, lower case."""
        lowered = name.lower()
        for packed in cls.PACKED:
            if lowered.endswith(packed):
                return lowered[: -len(packed)]
        return lowered

    @classmethod
    def _named(cls, literal: str, data: dict[str, list[str]]) -> str | None:
        """The one data file a literal names, or None when it names none or more than one."""
        normal = literal.replace("\\", "/")
        while normal.startswith(("./", "../")):
            normal = normal[normal.index("/") + 1 :]
        if not normal or normal.startswith("~") or "$" in normal or "{" in normal:
            return None
        found = data.get(cls._bare(normal.rsplit("/", 1)[-1]))
        if not found:
            return None
        if "/" in normal:
            tail = "/" + cls._bare(normal)
            found = [p for p in found if ("/" + cls._bare(p)).endswith(tail)]
        return found[0] if len(found) == 1 else None

    # -- how the code names it -----------------------------------------------------------------

    @classmethod
    def _literals(cls, line: str) -> list[str]:
        """The string literals of a line that end with a data suffix (compressed or not)."""
        out: list[str] = []
        index, length = 0, len(line)
        while index < length:
            quote = line[index]
            if quote not in "'\"`":
                index += 1
                continue
            end = index + 1
            while end < length and line[end] != quote:
                end += 2 if line[end] == "\\" else 1
            value = line[index + 1 : end]
            bare = cls._bare(value)
            if bare.endswith(cls.SUFFIXES) and len(value) <= 300:
                out.append(value)
            index = end + 1
        return out

    @classmethod
    def _beside_a_parser(cls, lines: list[str], number: int) -> bool:
        """Whether the naming at `lines[number]` is beside a parser and no runner. A line that only assigns a
        path to a name (no parser on it) is judged by the name's other uses: every one must be beside a parser."""
        assigned = cls._ASSIGNED.match(lines[number])
        if assigned is None or cls._parses(lines[number]):
            return cls._context(lines, number)
        pattern = re.compile(rf"(?<![\w$.]){re.escape(assigned.group(1))}(?![\w$])")
        uses = [i for i, line in enumerate(lines) if i != number and pattern.search(line)]
        return bool(uses) and all(cls._context(lines, i) for i in uses)

    @classmethod
    def _context(cls, lines: list[str], number: int) -> bool:
        """Parser calls beside `lines[number]`, and none that runs or loads."""
        beside = "\n".join(lines[max(0, number - BESIDE) : number + BESIDE + 1])
        names = cls._names(beside)
        if any(n.rsplit(".", 1)[-1] in cls.RUNNERS and n != "re.compile" for n in names):
            return False
        if any(n.startswith(("subprocess.", "child_process.")) for n in names):
            return False
        return cls._parses(beside)

    @staticmethod
    def _names(text: str) -> list[str]:
        """The identifiers and dotted names of a text (`json.load`, `JSON.parse`): words made of letters, digits, `_`, `$` and `.`."""
        return "".join(c if c.isalnum() or c in "_$." else " " for c in text).split()

    @classmethod
    def _parses(cls, text: str) -> bool:
        """Whether the text calls a parser (`require` of a `.json` file is one: Node reads it as JSON)."""
        names = cls._names(text)
        return any(n in cls.PARSERS for n in names) or (
            "require" in names and ".json" in text.lower()
        )


__all__ = ["DataRoles"]
