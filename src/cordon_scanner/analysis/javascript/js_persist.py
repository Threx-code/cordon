"""Which lines of a JavaScript file only name a persistence location -- the JavaScript twin of
`analysis/python/py_persist.py` (review 98 G6).

The pattern tier sees `LaunchAgents`, `~/.bashrc`, `crontab` or `/etc/systemd/system` and takes the
line as a foothold planted. Benign npm packages name them without writing them: a CLI reading the
plist of the service it manages, a dashboard whose form field is of type `'crontab'`, an installer
printing a tip about `~/.bashrc`, a config object holding a unit path. Each literal naming such a
location is labelled by its text and followed with JsFlow's own propagation (`_Analysis(text,
seed=...)`: bindings, destructuring, callbacks, promise chains, the file's own functions), and it is
WRITTEN when its value reaches a sink.

Sinks fail safe. Every call handed the value is one, except what only reads, tests or formats a
path or a string (`readFileSync`, `existsSync`, `path.join`, `.includes`, `console.log`, `JSON`,
`new Error`) and the file's own functions, which the propagation follows into. A process started
with it is a write, and so is a function the file imports from elsewhere: what that does is not read
here. A line keeps its pattern hit unless every persistence word on it sits inside a string or a
comment and no literal on it is written; a file JsFlow does not analyse keeps every hit.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any, ClassVar, Final, TypeVar

from cordon_scanner.foundation.models import Capability

if TYPE_CHECKING:
    from cordon_scanner.analysis.javascript.js_flow import _Analysis
    from cordon_scanner.foundation.content import FileContent

Hit = TypeVar("Hit")

#: Text any persistence pattern contains, case-insensitively: a superset of the rules' patterns.
PERSIST_WORD: Final = re.compile(
    r"(?i)bashrc|bash_profile|zshrc|\.profile|crontab|/etc/cron|launch(?:agents|daemons)|systemd"
    r"|systemctl|wantedby|currentversion|sitecustomize|usercustomize|startup|autostart"
)
PREFIX: Final = "persist:"
#: The work `_written` may do on one file, in token reads: every call-site search reads the whole
#: file, every argument followed counts one. Counted, not timed, so a verdict never depends on the
#: machine (#23). Past it, the file keeps every hit: a 350 KB bundle whose helpers are called
#: from hundreds of places needs some 17 million reads and is left to the patterns.
BUDGET: Final = 2_000_000


class JsPersistence:
    #: Calls that only read, test or format what they are given.
    READS: ClassVar[frozenset[str]] = frozenset(
        {
            "readFile", "readFileSync", "readText", "existsSync", "exists", "stat", "statSync",
            "lstat", "lstatSync", "access", "accessSync", "readdir", "readdirSync", "join",
            "resolve", "dirname", "basename", "extname", "normalize", "relative", "homedir",
            "includes", "startsWith", "endsWith", "indexOf", "replace", "replaceAll", "split",
            "toString", "trim", "toLowerCase", "toUpperCase", "slice", "substring", "match",
            "test", "concat", "format", "stringify", "parse", "String", "log", "warn", "error",
            "info", "debug", "trace", "t", "Error", "TypeError", "RangeError", "push", "set",
            "get", "has", "freeze", "assign", "keys", "values", "entries", "map", "filter",
            "forEach", "some", "every", "find", "sort", "fileURLToPath", "pathToFileURL",
        }
    )  # fmt: skip

    #: Words a `(` follows that are not calls.
    KEYWORDS: ClassVar[frozenset[str]] = frozenset(
        {"if", "while", "for", "switch", "catch", "return", "typeof", "void", "await", "yield",
         "with", "function", "do", "else", "in", "of", "instanceof", "delete", "throw", "case"}
    )  # fmt: skip

    @staticmethod
    def seed(value: str) -> str | None:
        """The label of a literal naming a persistence location: its own text, so each literal's
        reach is told apart."""
        return PREFIX + value[:200] if PERSIST_WORD.search(value) else None

    @classmethod
    def drop_named_only(cls, content: FileContent, hits: Sequence[Hit]) -> list[Hit]:
        """`hits` without the persistence pattern hits on lines that only name a location (the
        capability detector's filter for JavaScript, as `PythonAnalyzer.excused_lines` is Python's)."""
        if not any(getattr(h, "capability", None) is Capability.PERSIST for h in hits):
            return list(hits)
        lines = cls.named_only_lines(content.text)
        if not lines:
            return list(hits)
        starts = content.line_starts

        def line_of(hit: Hit) -> int:
            return getattr(hit, "line", 0) or bisect_right(starts, getattr(hit, "byte_start", 0))

        return [
            h
            for h in hits
            if not (getattr(h, "capability", None) is Capability.PERSIST and line_of(h) in lines)
        ]

    @classmethod
    def named_only_lines(cls, text: str) -> frozenset[int]:
        """Lines that name a persistence location only in literals no sink receives; empty when
        the file is not analysed."""
        from cordon_scanner.analysis.javascript.js_flow import MAX_BYTES, _Analysis, _OverBudget

        if len(text) > MAX_BYTES or not PERSIST_WORD.search(text):
            return frozenset()
        try:
            analysis = _Analysis(text, seed=cls.seed)
            analysis.run()
            written = cls._written(analysis)
        except (RecursionError, _OverBudget):
            return frozenset()
        literal_lines: dict[int, set[str]] = {}
        for i in range(analysis.n):
            fact = analysis.fact[i]
            if fact is not None and fact[0] == "src" and str(fact[1]).startswith(PREFIX):
                literal_lines.setdefault(analysis.line(i), set()).add(str(fact[1]))
        out: set[int] = set()
        for row, line in enumerate(text.splitlines(), 1):
            labels = literal_lines.get(row)
            if not labels or labels & written:
                continue
            if PERSIST_WORD.search(cls._code_of(line)) is None:
                out.add(row)
        return frozenset(out)

    @staticmethod
    def _code_of(line: str) -> str:
        """A line with its strings, templates and comments blanked: what is left is code."""
        out: list[str] = []
        quote = ""
        i = 0
        while i < len(line):
            ch = line[i]
            if quote:
                if ch == "\\":
                    i += 1
                elif ch == quote:
                    quote = ""
                out.append(" ")
            elif ch in "'\"`":
                quote = ch
                out.append(" ")
            elif line.startswith("//", i):
                break
            elif line.startswith("/*", i):
                end = line.find("*/", i + 2)
                if end < 0:
                    break
                out.append(" " * (end + 2 - i))
                i = end + 1
            else:
                out.append(ch)
            i += 1
        return "".join(out)

    @classmethod
    def _written(cls, a: _Analysis) -> set[str]:
        """The labels of every persistence literal a sink receives."""
        out: set[str] = set()
        # Call sites by function and labels by parameter, each found once: a bundle's helpers are
        # called from thousands of places, and `_call_sites` reads the whole file.
        sites: dict[Any, list[int]] = {}
        memo: dict[tuple[Any, int], set[str]] = {}
        spent = [0]
        for k in range(a.n - 1):
            if not (a.is_name(k) and a.is_p(k + 1, "(") and a.match[k + 1] > k and a._called(k)):
                continue
            name = str(a.t[k].value)
            if name in cls.KEYWORDS:
                continue
            scope = a.scope_of(k)
            if a.fn_by_name.get(a.resolve(name, scope)) is not None:
                continue  # the file's own function: followed by the propagation
            if name in cls.READS and a._sink_kind(k, scope) not in ("process", "execute"):
                continue
            carried: set[object] = set()
            for s, e in a._args(k + 1):
                carried |= a.taint(s, e, scope)
                cls._spend(spent, 1)
            start = a._chain(k)[1]
            if start < k:
                carried |= a.taint(start, k, scope)
            out |= cls._labels(a, carried, 0, sites, memo, spent)
        return out

    @staticmethod
    def _spend(spent: list[int], reads: int) -> None:
        from cordon_scanner.analysis.javascript.js_flow import _OverBudget

        spent[0] += reads
        if spent[0] > BUDGET:
            raise _OverBudget

    @classmethod
    def _labels(
        cls,
        a: _Analysis,
        carried: set[object],
        depth: int,
        sites: dict[Any, list[int]],
        memo: dict[tuple[Any, int], set[str]],
        spent: list[int],
    ) -> set[str]:
        """The persistence labels in `carried`, a parameter of the file's own function resolved to
        what every call of it passes (`put('/etc/systemd/system/x.service', unit)`). A parameter
        being resolved reads as nothing more while it is (a recursive helper)."""
        out = {str(x) for x in carried if isinstance(x, str) and x.startswith(PREFIX)}
        if depth >= 3:
            return out
        for x in carried:
            if isinstance(x, tuple) and len(x) == 3 and x[0] == "P":
                _, fid, idx = x
                if (fid, idx) not in memo:
                    memo[(fid, idx)] = set()
                    if fid not in sites:
                        cls._spend(spent, a.n)
                        sites[fid] = a._call_sites(fid)
                    found: set[str] = set()
                    for site in sites[fid]:
                        args = a._args(site + 1)
                        if idx < len(args):
                            given = a.taint(args[idx][0], args[idx][1], a.scope_of(site))
                            cls._spend(spent, 1)
                            found |= cls._labels(a, given, depth + 1, sites, memo, spent)
                    memo[(fid, idx)] = found
                out |= memo[(fid, idx)]
        return out


__all__ = ["JsPersistence"]
