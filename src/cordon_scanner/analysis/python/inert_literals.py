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
    def _spans(cls, source: str, focus: frozenset[int]) -> frozenset[tuple[int, int]]:
        """UTF-8 byte spans of the focus-line literals that reach no sink. Empty on a syntax error
        or past the seed limit, so nothing is lowered on a file this cannot read."""
        try:
            tree = PythonSyntax.parse(source)
        except (SyntaxError, ValueError):
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


# Spans of the files a scan read, keyed by their bytes: emptied after each scan with the other caches
# that hold a scan's files (foundation/collector).
ScanCaches.register(InertLiterals._CACHE)

__all__ = ["InertLiterals"]
