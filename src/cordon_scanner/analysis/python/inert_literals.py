"""A command-shaped string literal that is only data: it reaches no sink by the Python AST.

A security tool's deny-list, a red-team corpus, a validator's rule table or a test case carries
``rm -rf /``, a miner command line, a reverse-shell one-liner or a ``curl | sh`` as a STRING it
inspects, never a command it runs. `nerfstudio`'s beacon and a dropper carry theirs the other way --
into ``os.system``, ``subprocess.run``, ``exec``, a file that is then run, or out over the network.
The difference is reachability, not where the string sits, so a payload handed to a helper that runs
it is not inert however many calls deep.

The caller gives the lines a command-shaped finding matched; `all_inert` seeds only the literals on
those lines (a red-team file holds thousands of attack strings, past the flow's seed limit, so
seeding the whole file would read none of them) and follows each through names (per function scope),
attributes, containers, f-strings, and the parameters and returns of the file's own functions
(`PythonValueFlow`, which `py_persist` and `py_decoded` share). It over-approximates on purpose -- a
value that MAY reach a sink is treated as reaching one -- so a literal is called inert only when it
provably cannot run, send or be written out. A finding on such a literal is graded down to a
reported LOW, never dropped: the string is there, a reviewer may want it, but it executes nothing
(census D).
"""

from __future__ import annotations

import ast
import re
from collections.abc import Sequence
from typing import ClassVar

from cordon_scanner.analysis.python.py_flow import Label, PythonValueFlow
from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.foundation.capabilities import Capability
from cordon_scanner.foundation.collector import ScanCaches


class InertLiterals(PythonValueFlow):
    """Which of a file's seeded string literals reach a sink, and which are only data."""

    #: The suspect composites whose block rests on a single command-shaped capability, and that
    #: capability -- the hits whose spans must be inert for the finding to be a reported LOW. The
    #: MALICIOUS forms never reach the ceiling cascade. DROPPER is left out: it is a multi-capability
    #: composite, and its REMOTE_CODE form is JavaScript, which this Python check does not read.
    CAP: ClassVar[dict[str, Capability]] = {
        "SUSPECT.DESTROY.HOME_OR_ROOT.001": Capability.DESTROY,
        "SUSPECT.CRYPTOMINER.001": Capability.MINE,
    }
    #: Run source directly.
    _RUN: ClassVar[frozenset[str]] = frozenset(["exec", "eval", "compile"])
    #: Leave the host, by method or function name, over the file (over-approximate on purpose).
    #: These carry a payload out whatever its shape, so any seeded literal reaching one is live.
    _SENDERS: ClassVar[frozenset[str]] = frozenset(
        [
            "post",
            "put",
            "patch",
            "delete",
            "request",
            "urlopen",
            "urlretrieve",
            "send",
            "sendto",
            "sendall",
            "sendmail",
        ]
    )
    #: Fetch verbs: a URL literal handed to ``requests.get`` / ``session.head`` / ``httpx.get``
    #: goes out on the wire and pulls a payload back -- the `fjkslfjsdgbjkbnjfdkq` miner downloads
    #: xmrig that way. But `get`/`head` are also the commonest dict/attr lookups (a security
    #: scanner's IOC table and cord-engine are full of ``data.get(...)``), so these count as a sink
    #: ONLY for a URL-shaped value: a ``rm -rf /`` or an ``xmrig`` regex token handed to ``.get``
    #: is a lookup, not a download, and stays inert.
    _FETCH: ClassVar[frozenset[str]] = frozenset(["get", "head"])
    #: A seeded value is URL-shaped when it opens with one of these schemes.
    _URL_SCHEMES: ClassVar[tuple[str, ...]] = ("http://", "https://", "ftp://")
    #: Stratum is the mining pool wire protocol and exists for nothing else. A stratum URL is not a
    #: command a tool merely inspects; it is mining configuration. Paired in the same file with a
    #: payout wallet (``POOL = "stratum+tcp://..."`` beside ``WALLET = "4A..."``) it is mining by
    #: definition, so such a literal is never graded inert even when it reaches no sink -- that pair
    #: is the control `SUSPECT.CRYPTOMINER.001` rests on. A security tool's IOC table carries the
    #: protocol pattern but not a specific attacker wallet, so the pairing is what separates the two.
    _STRATUM_SCHEMES: ClassVar[tuple[str, ...]] = ("stratum+tcp://", "stratum+ssl://", "stratum://")
    #: A payout-wallet-shaped literal: a long base58 run (Monero is 95 chars, integrated 106), the
    #: kind of address a miner is configured to pay. Scanned only to decide whether a stratum pool
    #: literal in the same file is configuration rather than a listed indicator.
    _WALLET: ClassVar[re.Pattern[str]] = re.compile(r"[1-9A-HJ-NP-Za-km-z]{90,110}")
    #: Write the value out. A command written to a file is the first half of write-then-run, and
    #: telling that from a benign log needs the file traced to an exec; kept as a sink so the
    #: write-then-run dropper is never called inert.
    _WRITES: ClassVar[frozenset[str]] = frozenset(
        ["write", "write_text", "write_bytes", "writelines"]
    )
    #: Inert byte spans per (content hash, focus lines), bounded.
    _CACHE: ClassVar[dict[tuple[int, frozenset[int]], frozenset[tuple[int, int]]]] = {}

    def __init__(self, tree: ast.AST, focus: frozenset[int] | None = None) -> None:
        super().__init__(tree)
        self._focus = focus
        #: Seeded lines whose literal is URL-shaped -- the only ones a fetch verb makes live.
        self._url_seeds: set[int] = set()
        #: Seeded lines whose literal is a stratum pool URL -- never inert when the file also holds
        #: a wallet-shaped literal (mining configuration, not a listed indicator).
        self._stratum_seeds: set[int] = set()

    def seed(self, node: ast.AST) -> Label | None:
        """A non-blank string literal on a focus line (every line when `focus` is None), by line.

        A URL-shaped literal also records its line in `_url_seeds`, so a fetch verb can be made a
        sink for it alone. A stratum pool literal records its line in `_stratum_seeds`. A line that
        carries more than one kind is recorded under each, which over-approximates toward keeping
        the finding.
        """
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value.strip()
            and (self._focus is None or node.lineno in self._focus)
        ):
            low = node.value.strip().lower()
            if low.startswith(self._URL_SCHEMES):
                self._url_seeds.add(node.lineno)
            if any(scheme in low for scheme in self._STRATUM_SCHEMES):
                self._stratum_seeds.add(node.lineno)
            return node.lineno
        return None

    def _is_sink(self, node: ast.Call) -> bool:
        """A call whose arguments run, are executed, leave the host, or are written out. Fetch
        verbs are handled separately in `_reached`, since they are a sink only for a URL."""
        name = self.name(node.func)
        return (
            self.dotted(node.func) in PythonValueFlow.PROCESS
            or name in PythonValueFlow.PROCESS
            or name in self._RUN
            or name in self._SENDERS
            or name in self._WRITES
        )

    def _reached(self) -> set[Label]:
        reached: set[Label] = set()
        for node in self.calls:
            if self._is_sink(node):
                reached |= self.given(node)
            elif self.name(node.func) in self._FETCH:
                # A fetch (`get`/`head`) is a sink only for a URL-shaped value, so a plain command
                # string flowing into a dict/attr `.get()` lookup stays inert.
                reached |= self.given(node) & self._url_seeds
        # A stratum pool literal beside a payout wallet is mining configuration, not a listed
        # indicator, so it is live however it is (or is not) used. The pairing is what tells it from
        # a security tool's IOC table, which lists the protocol but not a specific attacker wallet.
        if self._stratum_seeds and self._has_wallet():
            reached |= self._stratum_seeds
        return reached

    def _has_wallet(self) -> bool:
        """Whether any string literal in the file is payout-wallet-shaped."""
        return any(
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and self._WALLET.search(node.value)
            for node in ast.walk(self.tree)
        )

    @classmethod
    def inert_lines(cls, tree: ast.AST) -> frozenset[int]:
        """Lines whose string literal(s) reach no sink, seeding the whole file. For small inputs and
        the unit tests; `all_inert` is the focused form the detector uses."""
        analysis = cls(tree)
        if not analysis.index():
            return frozenset()
        analysis.flow()
        return frozenset(set(analysis.seeds.values()) - analysis._reached())

    @classmethod
    def quoted_call_spans(cls, source: str) -> tuple[tuple[int, int, int, int], ...] | None:
        """(first line, first column, last line, end column) of every string literal with call
        syntax in it (a `(`) that is not an f-string's and reaches no sink, for a file in which no
        string is run as code: None when the source does not parse, when it names `exec`, `eval`,
        `compile` or `execfile` anywhere (then any text in it may be a program), or when it holds
        more literals than the flow reads. A literal that is handed to a process, sent, or written
        out (the first half of write-then-run) is not text and has no span here: the same sinks
        that keep a command in a string live for `all_inert`. Call-like text that nothing uses (a
        table of the calls a scanner or a guard looks for, a docstring showing a call) is not a
        call."""
        try:
            tree = PythonSyntax.shared(source)
        except (SyntaxError, ValueError, RecursionError):
            # S2: an excuse; failing excuses nothing, so the finding it would lower stands
            return None
        for node in PythonSyntax.of(tree, ast.Name, ast.Attribute):
            if (node.id if isinstance(node, ast.Name) else node.attr) in cls._RUN | {"execfile"}:
                return None
        parents = PythonSyntax.parents(tree)
        quoted = [
            node
            for node in PythonSyntax.of(tree, ast.Constant)
            if isinstance(node.value, str)
            and "(" in node.value
            and node.end_lineno is not None
            and node.end_col_offset is not None
            and not isinstance(parents.get(id(node)), ast.JoinedStr | ast.FormattedValue)
        ]
        if not quoted:
            return ()
        # The flow annotates nodes, so it reads a parse of its own (`PythonSyntax.shared`).
        analysis = cls(PythonSyntax.parse(source), focus=frozenset(node.lineno for node in quoted))
        if not analysis.index():
            return None
        analysis.flow()
        reached = analysis._reached()
        if any(node.lineno in reached for node in quoted):
            # A pattern records only its first match: a table of call names ahead of the call text
            # that is staged and run would stand for it. One literal in use makes the file's call
            # text live, all of it.
            return ()
        return tuple(
            (node.lineno, node.col_offset, node.end_lineno, node.end_col_offset)
            for node in quoted
            if node.end_lineno is not None and node.end_col_offset is not None
        )

    @classmethod
    def _spans(cls, source: str, focus: frozenset[int]) -> frozenset[tuple[int, int]]:
        """UTF-8 byte spans of the focus-line literals that reach no sink. Empty on a syntax error
        or past the seed limit, so nothing is lowered on a file this cannot read."""
        try:
            tree = PythonSyntax.parse(source)
        except (SyntaxError, ValueError):
            # S2: an excuse; failing excuses nothing, so the finding it would lower stands
            return frozenset()
        analysis = cls(tree, focus=focus)
        if not analysis.index():
            return frozenset()
        analysis.flow()
        reached = analysis._reached()
        line_start: dict[int, int] = {1: 0}
        line = 1
        for index, byte in enumerate(source.encode("utf-8")):
            if byte == 0x0A:
                line += 1
                line_start[line] = index + 1
        spans: set[tuple[int, int]] = set()
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and node.lineno in focus
                and node.lineno not in reached
                and node.end_lineno is not None
                and node.end_col_offset is not None
                and node.lineno in line_start
                and node.end_lineno in line_start
            ):
                spans.add(
                    (
                        line_start[node.lineno] + node.col_offset,
                        line_start[node.end_lineno] + node.end_col_offset,
                    )
                )
        return frozenset(spans)

    @classmethod
    def all_inert(cls, path: str, text: str, raw: bytes, hits: list[tuple[int, int, int]]) -> bool:
        """Whether every hit `(byte_start, byte_end, line)` lies inside an inert literal span.

        Python only. A command on the same line but in code (``os.system("rm -rf /")``) is not
        inside an inert span and keeps its grade; a non-Python file, a syntax error or a file past
        the seed limit yields no inert spans.
        """
        if not path.rpartition("!")[2].endswith((".py", ".pyw")) or not hits:
            return False
        focus = frozenset(line for _, _, line in hits)
        key = (hash(raw), focus)
        spans = cls._CACHE.get(key)
        if spans is None:
            if len(cls._CACHE) > 256:
                cls._CACHE.clear()
            spans = cls._spans(text, focus)
            cls._CACHE[key] = spans
        # Overlap, not containment: a capability's regex captures context around the command (the
        # `;` inside `"a; rm -rf /"` reads as a shell separator, so the hit begins at the code
        # before the string), so a hit can start outside the literal that holds the command. Overlap
        # is still safe -- a literal that reaches a sink has no inert span, so a live command never
        # overlaps one -- while containment would miss the command that is genuinely only data.
        return all(
            any(start < byte_end and byte_start < end for start, end in spans)
            for byte_start, byte_end, _ in hits
        )


class TextLiterals(InertLiterals):
    """Which path or host literals of a file are only data: a table the code matches text against,
    not a place it reads or sends to.

    A secret scanner, a redactor and a security tool carry the credential stores of a dozen services
    and the hosts a drop point is known by as STRINGS they look for in what they read; a stealer
    carries the same strings and OPENS them. The pattern tier reads both the same way. This
    follows each literal on the given lines (`PythonValueFlow`, as `InertLiterals` does) and calls
    it data when it reaches no use: a use is every call except those that only test, match, format,
    show or store a value (`CONSUMERS`), so `open`, `Path`, `glob`, `connect`, a request, a function
    of another file and anything not named here keep the hit. A consumer's result carries the value
    on (`carries`), so a use further along still sees it: `lower()` then `open()` is a use. A file
    that names `exec`, `eval`, `compile` or `execfile` anywhere may run any string, so it yields no
    data spans (the same guard as `quoted_call_spans`).
    """

    #: Calls (and method names) that only test, match, format, show or store the value they are given.
    CONSUMERS: ClassVar[frozenset[str]] = frozenset(
        [
            # matching and comparing text
            "search",
            "match",
            "fullmatch",
            "sub",
            "subn",
            "findall",
            "finditer",
            "split",
            "rsplit",
            "splitlines",
            "partition",
            "rpartition",
            "escape",
            "fnmatch",
            "fnmatchcase",
            "startswith",
            "endswith",
            "find",
            "rfind",
            "index",
            "rindex",
            "count",
            "removeprefix",
            "removesuffix",
            # formatting text
            "lower",
            "upper",
            "casefold",
            "strip",
            "lstrip",
            "rstrip",
            "replace",
            "format",
            "format_map",
            "join",
            "encode",
            "decode",
            "title",
            "capitalize",
            "ljust",
            "rjust",
            "center",
            "expandtabs",
            "translate",
            "dedent",
            "indent",
            "fill",
            "wrap",
            # keeping values in containers
            "append",
            "add",
            "extend",
            "update",
            "insert",
            "setdefault",
            "get",
            "items",
            "keys",
            "values",
            "pop",
            "sorted",
            "list",
            "tuple",
            "set",
            "frozenset",
            "dict",
            "enumerate",
            "reversed",
            "zip",
            "len",
            "min",
            "max",
            "any",
            "all",
            "sum",
            "iter",
            "next",
            "OrderedDict",
            "defaultdict",
            "namedtuple",
            "field",
            # showing it to a person
            "print",
            "debug",
            "info",
            "warning",
            "warn",
            "error",
            "exception",
            "critical",
            "log",
            "repr",
            "str",
            "bool",
            "int",
            "float",
            "isinstance",
            "type",
            "id",
            "hash",
        ]
    )
    #: Names an HTTP request is made through: `get` and `head` on these send what they are given.
    _HTTP: ClassVar[frozenset[str]] = frozenset(
        [
            "requests",
            "httpx",
            "aiohttp",
            "urllib",
            "urllib3",
            "http",
            "https",
            "session",
            "client",
            "curl_cffi",
            "pycurl",
        ]
    )
    #: Modules whose functions of any name only match or compare text (`re.compile`, not the builtin).
    MATCHING: ClassVar[frozenset[str]] = frozenset(["re", "regex", "fnmatch", "difflib"])
    #: Spans per (content hash, focus lines): its own table, as `InertLiterals._CACHE` is another analysis.
    _DATA_CACHE: ClassVar[dict[tuple[int, frozenset[int]], frozenset[tuple[int, int]]]] = {}

    def _is_sink(self, node: ast.Call) -> bool:
        """A use: every call that is not a consumer, whatever it is called or wherever it is defined."""
        dotted = self.dotted(node.func) or ""
        if dotted.partition(".")[0] in self.MATCHING:
            return False
        return self.name(node.func) not in self.CONSUMERS

    def _reached(self) -> set[Label]:
        reached: set[Label] = set()
        for node in self.calls:
            if self._is_sink(node):
                reached |= self.given(node)
            elif self.name(node.func) in self._FETCH:
                # `requests.get(url)` sends: a fetch verb is a use for a URL-shaped value, as in
                # `InertLiterals`, and for any value when it is called on an HTTP client or
                # module (`requests.get('https://' + host)`); `data.get(key)` is a lookup.
                if (self.dotted(node.func) or "").partition(".")[0] in self._HTTP:
                    reached |= self.given(node)
                else:
                    reached |= self.given(node) & self._url_seeds
        return reached

    @classmethod
    def data_spans(
        cls, source: str, raw: bytes, focus: frozenset[int]
    ) -> frozenset[tuple[int, int]]:
        """UTF-8 byte spans of the string literals on `focus` lines that reach no use; empty when
        the source does not parse, names a way to run a string, or holds more literals than the
        flow reads, so nothing is dropped on a file this cannot read."""
        key = (hash(raw), focus)
        spans = cls._DATA_CACHE.get(key)
        if spans is None:
            if len(cls._DATA_CACHE) > 256:
                cls._DATA_CACHE.clear()
            spans = cls._data(source, focus)
            cls._DATA_CACHE[key] = spans
        return spans

    @classmethod
    def spans_at(cls, text: str, raw: bytes, offsets: Sequence[int]) -> tuple[tuple[int, int], ...]:
        """The data-only literals that hold any of the byte `offsets`, as sorted byte spans."""
        focus = frozenset(raw.count(b"\n", 0, offset) + 1 for offset in offsets)
        return tuple(sorted(cls.data_spans(text, raw, focus)))

    @classmethod
    def _runs_a_string(cls, tree: ast.AST) -> bool:
        """Whether the file names a way to run a string: `exec`, `eval`, the builtin `compile`,
        `execfile` or `__import__`. A method of that name (`re.compile`, `pattern.exec`) is not the
        builtin, and `from re import compile` makes the bare name the matcher; `builtins.compile`
        is the builtin."""
        matcher = any(
            isinstance(node, ast.ImportFrom)
            and (node.module or "").partition(".")[0] in cls.MATCHING
            and any(alias.name == "compile" for alias in node.names)
            for node in ast.walk(tree)
        )
        named = cls._RUN | {"execfile", "__import__"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id in named:
                if node.id == "compile" and matcher:
                    continue
                return True
            if isinstance(node, ast.Attribute):
                builtin = isinstance(node.value, ast.Name) and node.value.id in (
                    "builtins",
                    "__builtins__",
                )
                if node.attr in ("exec", "eval", "execfile") or (builtin and node.attr in named):
                    return True
        return False

    @classmethod
    def _data(cls, source: str, focus: frozenset[int]) -> frozenset[tuple[int, int]]:
        try:
            tree = PythonSyntax.parse(source)
        except (SyntaxError, ValueError):
            # S2: an excuse; failing excuses nothing, so the finding it would lower stands
            return frozenset()
        if cls._runs_a_string(tree):
            return frozenset()
        return cls._spans(source, focus - cls._exported_lines(tree))

    @classmethod
    def _exported_lines(cls, tree: ast.AST) -> frozenset[int]:
        """Lines whose literals another module may read: a module-level or class-level constant, and
        the body of a function, that nothing in this file refers to. A constant written for an
        importer to send to (`__init__.py` holding the host a sibling module posts to) is not a
        table this file matches text against, whichever consumers it names, so it is never data."""
        loaded = {
            node.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
        } | {
            node.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load)
        }
        lines: set[int] = set()
        holders = [tree, *(n for n in ast.walk(tree) if isinstance(n, ast.ClassDef))]
        for holder in holders:
            in_class = isinstance(holder, ast.ClassDef)
            for stmt in getattr(holder, "body", ()):
                if isinstance(stmt, ast.Assign | ast.AnnAssign):
                    targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                    named = {t.id for t in targets if isinstance(t, ast.Name)}
                    # A class attribute is read through an instance (`self.url`) or the class, which
                    # the flow does not follow: always left to the importers and the methods.
                    unread = in_class or (bool(named) and not named & loaded)
                elif isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef):
                    unread = stmt.name not in loaded
                else:
                    continue
                if unread:
                    lines.update(range(stmt.lineno, (stmt.end_lineno or stmt.lineno) + 1))
        return frozenset(lines)


# Spans of the files a scan read, keyed by their bytes: emptied after each scan with the other caches
# that hold a scan's files (foundation/collector).
ScanCaches.register(InertLiterals._CACHE)
ScanCaches.register(TextLiterals._DATA_CACHE)

__all__ = ["InertLiterals", "TextLiterals"]
