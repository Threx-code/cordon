"""cordon-rule string search: where each string of a rule matches in the data.

A declared string becomes a `Search`: one or more `Part`s (a hex pattern with a long jump is cut
into linked parts at the jump, each found on its own and joined when the distance fits), each with
the anchors its search looks for. The search walks the data once per anchor; every place an
anchor occurs is checked in turn -- text compared, patterns run forwards from the anchor and
backwards from it for every start the match can have -- in the order of where the anchor ends,
longer anchors first, later-declared anchors first.
"""

from __future__ import annotations

import bisect
import re
import time
from collections.abc import Iterable, Iterator, Sequence
from typing import Any, ClassVar

from cordon_scanner.detect.binary.rule_engine.anchoring.along import Along
from cordon_scanner.detect.binary.rule_engine.anchoring.automaton import Compare as _Compare
from cordon_scanner.detect.binary.rule_engine.anchoring.automaton import (
    HexFind,
    TextCheck,
    TextFind,
)
from cordon_scanner.detect.binary.rule_engine.anchoring.places import Places
from cordon_scanner.detect.binary.rule_engine.anchoring.stream import Streams
from cordon_scanner.detect.binary.rule_engine.anchors import Anchor, Anchors
from cordon_scanner.detect.binary.rule_engine.chain import Chain
from cordon_scanner.detect.binary.rule_engine.hits import Hits
from cordon_scanner.detect.binary.rule_engine.pattern import (
    GAP,
    LIT,
    SEQ,
    Bytes,
    PatternError,
    Program,
    Term,
    Unbounded,
)
from cordon_scanner.detect.binary.rule_engine.pattern_readers import (
    LINK_GAP,
    HexReader,
    RegexReader,
)
from cordon_scanner.detect.binary.rule_engine.search_parts import AnchorAt, Event, Part
from cordon_scanner.detect.binary.rule_engine.threads import REACH, Lanes, Threads

#: The most matches one string records; past this it is not searched further in that data.
MAX_HITS = 1_000_000


class Search:
    """A string, ready to be searched for. `flags` holds the modifiers that apply: nocase, wide,
    ascii, fullword, xor (lo, hi), base64, base64wide, dotall, greedy, plain."""

    METACHARS: ClassVar[bytes] = b"\\^$|()[]*?{,.+}"
    #: Every attribute a search holds: what a kept pack (`pack_cache`) pickles and restores.
    STATE: ClassVar[tuple[str, ...]] = (
        "flags",
        "parts",
        "needles",
        "folds",
        "zeros",
        "hex_layouts",
    )

    def __reduce__(self) -> tuple[Any, ...]:
        """Pickled as its state, restored without preparing it again. A compiled (mypyc) class
        is rebuilt by calling its constructor, so the default reduction -- a bare instance, then
        its `__dict__` -- does not apply; `_restore` builds the cheapest search there is and sets
        the kept state over it."""
        return (Search._restore, ({name: getattr(self, name) for name in Search.STATE},))

    @staticmethod
    def _restore(state: dict[str, Any]) -> Search:
        search = Search("text", b"\0", {})
        search.flags, search.parts = state["flags"], state["parts"]
        search.needles, search.folds, search.zeros = (
            state["needles"],
            state["folds"],
            state["zeros"],
        )
        search.hex_layouts = state["hex_layouts"]
        return search

    def __init__(self, kind: str, value: Any, modifiers: dict[str, Any]) -> None:
        self.flags: dict[str, Any] = dict(modifiers)
        self.parts: list[Part] = []
        #: The anchors to look for, by distinct bytes (`_index`), and the parts with none.
        self.needles: list[tuple[bytes, int, list[tuple[int, int, AnchorAt]]]] | None = None
        self.folds: list[tuple[bytes, int, dict[bytes, list[tuple[int, int, AnchorAt]]]]] = []
        self.zeros: list[tuple[int, int, AnchorAt]] = []
        #: A plain hex part's layouts for the native find (`HexFind`): None until worked out,
        #: False where it does not apply.
        self.hex_layouts: tuple[bytes, bytes] | bool | None = None
        f = self.flags
        if kind == "regex":
            source, marks = value
            if "i" in marks:
                f["nocase"] = True
            if "s" in marks:
                f["dotall"] = True
        if kind == "hex":
            f["dotall"] = True
        if "wide" not in f and "base64" not in f and "base64wide" not in f:
            f["ascii"] = True
        if kind == "text" and not ("base64" in f or "base64wide" in f):
            self._add_text(value)
            return
        plain = False
        if kind == "hex":
            reader = HexReader("{" + value + "}")
            root = reader.read()
            plain = reader.plain
        elif kind == "regex":
            r = RegexReader(source.encode("utf-8", "surrogateescape"))
            root = r.read()
            if r.eager and r.lazy:
                raise PatternError("greedy and lazy repeats mixed in one regular expression")
            f["greedy"] = r.eager
        else:
            root = RegexReader(self._base64_source(value)).read()
        f["plain"] = plain
        gap = (0, 0)
        for piece, next_gap in Search._links(root):
            literal = Search._literal(piece)
            if literal is not None:
                self._add_text(literal)
            else:
                self._add_pattern(piece)
            self.parts[-1].gap = gap
            gap = next_gap

    # -- building --------------------------------------------------------------

    @staticmethod
    def _links(root: Term) -> Iterator[tuple[Term, tuple[int, int]]]:
        """The pattern cut at each top-level lazy jump longer than `LINK_GAP`, with the jump."""
        while True:
            if root.kind != SEQ:
                yield root, (0, 0)
                return
            kids = root.kids
            for i, kid in enumerate(kids):
                if (kid.kind == GAP and not kid.eager and 0 < i < len(kids) - 1
                        and (kid.lo > LINK_GAP or kid.hi > LINK_GAP)):  # fmt: skip
                    yield Term(SEQ, *kids[:i]), (kid.lo, kid.hi)
                    root = Term(SEQ, *kids[i + 1 :])
                    break
            else:
                yield root, (0, 0)
                return

    @staticmethod
    def _literal(root: Term) -> bytes | None:
        if root.kind == LIT:
            return bytes([root.value])
        if root.kind != SEQ:
            return None
        for k in root.kids:
            if k.kind != LIT:
                return None
        return bytes([k.value for k in root.kids])

    def _add_text(self, text: bytes) -> None:
        f = self.flags
        part = Part()
        part.text = text
        part.fits = (len(text) * 2 if "wide" in f else len(text)) <= 4
        anchor, _ = Anchors.of_text(text)
        self.parts.append(part)
        part.anchors = self._finish([anchor], text=True)

    def _add_pattern(self, root: Term) -> None:
        part = Part()
        forward = Program(root, backwards=False)
        backward = Program(root, backwards=True)
        part.forward, part.backward = forward.ops, backward.ops
        part.root_entry = root.fwd
        part.factors = Part.factors_of(root)
        part.chain = Chain.of(root)
        part.heavy = Part.heavy_in(root)
        part.required = Part.literals_in(root)
        chosen, _ = Anchors.of(root)
        self.parts.append(part)
        part.anchors = self._finish(chosen, text=False)
        if not part.anchors:
            part.anchors = [(b"", 0, root.fwd, None)]

    def _finish(self, anchors: list[Anchor], *, text: bool) -> list[AnchorAt]:
        f = self.flags
        if "wide" in f and (text or not ("base64" in f or "base64wide" in f)):
            wide = Anchors.wide(anchors)
            anchors = anchors + wide if "ascii" in f else wide
        if "nocase" in f:
            anchors = anchors + Anchors.cases(anchors)
        if text and "xor" in f:
            lo, hi = f["xor"]
            anchors = Anchors.xored(anchors, lo, hi)
        out = []
        for a in anchors:
            fwd = a.term.fwd if a.term is not None else None
            back = a.term.back if a.term is not None else None
            out.append((bytes(a.data), a.back, fwd, back))
        return out

    def _base64_source(self, text: bytes) -> bytes:
        """The alternatives a base64 string can appear as, as a regular expression."""
        f = self.flags
        alphabet = next(
            (f[m] for m in ("base64", "base64wide") if isinstance(f.get(m), bytes)),
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        )
        forms: list[bytes] = []
        sources = []
        if "wide" in f:
            sources.append(Search.widen(text))
        if "ascii" in f or "wide" not in f:
            sources.append(text)
        for source in sources:
            if "base64" in f:
                forms += Search._encodings(source, alphabet, widened=False)
            if "base64wide" in f:
                forms += Search._encodings(source, alphabet, widened=True)
        out = bytearray(b"(")
        for i, form in enumerate(forms):
            if i:
                out += b"|"
            for b in form:
                if b == 0:
                    out += b"\\x00"
                elif b in Search.METACHARS:
                    out += bytes([0x5C, b])
                else:
                    out.append(b)
        out += b")"
        return bytes(out)

    @staticmethod
    def _encodings(text: bytes, alphabet: bytes, *, widened: bool) -> list[bytes]:
        """`text` encoded after 0, 1 and 2 bytes of filler, less the characters that depend on
        the bytes around it."""
        forms = []
        for shift in range(3):
            if shift == 1 and len(text) == 1:
                continue
            padded = b"A" * shift + text
            pad = (3 - len(padded) % 3) % 3
            enc = Search._encode(padded, alphabet)
            lead = shift + 1 if shift else 0
            trail = pad + 1 if pad else 0
            if len(enc) - lead - trail < 0:
                raise PatternError("a base64 string too short to search for")
            piece = enc[lead : len(enc) - trail]
            forms.append(Search.widen(piece) if widened else piece)
        return forms

    @staticmethod
    def _encode(data: bytes, alphabet: bytes) -> bytes:
        out = bytearray()
        for i in range(0, len(data) - len(data) % 3, 3):
            n = data[i] << 16 | data[i + 1] << 8 | data[i + 2]
            out += bytes([alphabet[n >> s & 63] for s in (18, 12, 6, 0)])
        rest = data[len(data) - len(data) % 3 :]
        if len(rest) == 1:
            out += bytes([alphabet[rest[0] >> 2], alphabet[(rest[0] & 3) << 4]]) + b"=="
        elif len(rest) == 2:
            n = rest[0] << 8 | rest[1]
            out += bytes([alphabet[n >> 10], alphabet[n >> 4 & 63], alphabet[(n & 15) << 2]])
            out += b"="
        return bytes(out)

    @staticmethod
    def widen(data: bytes) -> bytes:
        return b"".join([bytes([b, 0]) for b in data])

    # -- searching ---------------------------------------------------------------

    def find(
        self,
        data: bytes,
        fixed: int | None = None,
        deadline: float | None = None,
        seen: dict[Any, Any] | None = None,
    ) -> Sequence[tuple[int, int]]:
        """(offset, length) of each match, by offset. With `fixed`, only a match there counts.
        `seen` holds where each anchor occurs in `data`, shared by every string searched there,
        so each distinct anchor is looked for once per piece of data."""
        if self.needles is None:
            self._index()
        assert self.needles is not None  # noqa: S101 - set by _index
        seen = {} if seen is None else seen
        if not self._holds_required(data, seen):
            return []
        if Streams.wanted(self, data, seen):
            hunt = _Hunt(self, data, fixed, deadline)
            hunt.budget = Search.budget(seen)
            streamed = hunt.run_streamed(Streams.sources(self, data, seen, hunt))
            if streamed is not None:
                return streamed
        if TextFind.usable(self):
            return self._text_find(data, fixed, seen, deadline)
        if HexFind.layouts(self) is not None:
            return HexFind.hits(self, data, seen, fixed, MAX_HITS, deadline)
        events: list[Event] = []
        for needle, length, owners in self.needles:
            starts = seen.get(needle)
            if starts is None:
                gated = self._gated(data, needle, length, owners, seen)
                if gated is not None:
                    events.extend(gated)
                    continue
                starts = seen[needle] = Search.kept(seen, False, needle) or Search.occurrences(
                    data, needle, Search.budget(seen)
                )
            if starts:
                Search._occurred(events, starts, length, owners)
        for folded, length, spellings in self.folds:
            # every case spelling of an anchor is present, so one search of the lower-cased data
            # finds them all; the bytes found say which spelling it was
            starts = seen.get(("folded", folded))
            if starts is None:
                starts = Search.kept(seen, True, folded)
            if starts is None:
                lowered = seen.get(("lowered",))
                if lowered is None:
                    lowered = seen[("lowered",)] = data.lower()
                starts = Search.occurrences(lowered, folded, Search.budget(seen))
            seen[("folded", folded)] = starts
            for s in starts:
                Search._occurred(events, (s,), length, spellings[data[s : s + length]])
        hunt = _Hunt(self, data, fixed, deadline)
        hunt.budget = Search.budget(seen)
        for order, p, anchor in self.zeros:
            events.extend((at, 0, -order, p, anchor, at) for at in hunt.starts(p))
        if not events:
            return []
        events.sort(key=lambda e: (e[0], e[1], e[2]))
        return hunt.run(events)

    def _text_find(
        self, data: bytes, fixed: int | None, seen: dict[Any, Any], deadline: float | None
    ) -> Hits:
        """A text string's matches in one native call (`TextFind`), from each anchor's
        occurrences, found and kept in `seen` as `find` keeps them."""
        assert self.needles is not None  # noqa: S101 - set by _index
        owners = []
        for needle, length, holders in self.needles:
            starts = seen.get(needle)
            if starts is None:
                starts = seen[needle] = Search.kept(seen, False, needle) or Search.occurrences(
                    data, needle, Search.budget(seen)
                )
            owners += [
                (starts, length, length + a[1], order, len(a[0]) + a[1]) for order, _, a in holders
            ]
        for folded, length, spellings in self.folds:
            # a folded anchor's owners are those of how the data spells it at each occurrence
            starts = seen.get(("folded", folded))
            if starts is None:
                starts = Search.kept(seen, True, folded)
            if starts is None:
                lowered = seen.get(("lowered",))
                if lowered is None:
                    lowered = seen[("lowered",)] = data.lower()
                budget = Search.budget(seen)
                starts = Search.occurrences(lowered, folded, budget)
            seen[("folded", folded)] = starts
            spelled: dict[bytes, list[int]] = {}
            for at in starts:
                spelled.setdefault(data[at : at + length], []).append(at)
            for spelling, found in spelled.items():
                owners += [
                    (found, length, length + a[1], order, len(a[0]) + a[1])
                    for order, _, a in spellings[spelling]
                ]
        return TextFind.hits(self, data, owners, fixed, MAX_HITS, deadline)

    #: An anchor occurring more often than this has its forward gate run over the whole data at
    #: once (`_gated`) rather than tested at each occurrence.
    GATED: ClassVar[int] = 256

    def _gated(
        self,
        data: bytes,
        needle: bytes,
        length: int,
        owners: list[tuple[int, int, AnchorAt]],
        seen: dict[Any, Any],
    ) -> list[Event] | None:
        """The events of a common anchor, from its parts' forward gates run once over the data in
        C, rather than from every occurrence: an occurrence whose gate fails is one `_Hunt._check`
        turns away unread, so leaving it out changes no match. Only where that holds -- a pattern
        part, not `plain`, read one byte wide (no `wide`, `xor` or `base64`) -- and each gated
        position still has the anchor's bytes where it should. None to take every occurrence."""
        gates = Streams.gates(self, data, needle, owners, seen)
        budget = Search.budget(seen)
        if gates is None:
            return None
        events: list[Event] = []
        for (order, p, anchor), gate in zip(owners, gates, strict=True):
            lead = anchor[1]
            for found in gate.finditer(data):
                if len(events) >= min(Places.MOST, budget[0]):
                    raise Search.too_many()
                offset = found.start()
                at = offset + lead
                if data.startswith(needle, at):
                    events.append((at + length, -length, -order, p, anchor, offset))
        budget[0] -= len(events)
        return events

    def _holds_required(self, data: bytes, seen: dict[Any, Any]) -> bool:
        """Whether `data` holds every literal run each part's matches must hold
        (`Part.required`), read case-folded for a `nocase` string; one search of the data each,
        shared by every string."""
        f = self.flags
        if "wide" in f or "xor" in f or "base64" in f or "base64wide" in f:
            return True
        folded = "nocase" in f
        for part in self.parts:
            for run in part.required:
                key = ("holds", folded, run)
                held = seen.get(key)
                if held is None:
                    if folded:
                        lowered = seen.get(("lowered",))
                        if lowered is None:
                            lowered = seen[("lowered",)] = data.lower()
                        held = seen[key] = run.lower() in lowered
                    else:
                        held = seen[key] = run in data
                if not held:
                    return False
        return True

    @staticmethod
    def _occurred(
        events: list[Event],
        starts: Iterable[int],
        length: int,
        owners: list[tuple[int, int, AnchorAt]],
    ) -> None:
        for order, p, anchor in owners:
            back = length + anchor[1]
            events.extend(
                (s + length, -length, -order, p, anchor, s + length - back)
                for s in starts
                if back <= s + length
            )

    def _index(self) -> None:
        """The anchors of every part, by distinct bytes, numbered in the order they are checked
        when two end at the same place (a later one first). Anchors that are every case spelling
        of one run of bytes are looked for together, in the lower-cased data."""
        table: dict[bytes, list[tuple[int, int, AnchorAt]]] = {}
        zeros = []
        order = 0
        for p, part in enumerate(self.parts):
            for anchor in part.anchors:
                if anchor[0]:
                    table.setdefault(anchor[0], []).append((order, p, anchor))
                else:
                    zeros.append((order, p, anchor))
                order += 1
        spellings: dict[bytes, dict[bytes, list[tuple[int, int, AnchorAt]]]] = {}
        for needle, owners in table.items():
            spellings.setdefault(needle.lower(), {})[needle] = owners
        self.needles, self.folds = [], []
        for folded, group in spellings.items():
            letters = sum(1 for b in folded if 0x61 <= b <= 0x7A)
            if letters and len(group) == 1 << letters:
                self.folds.append((folded, len(folded), group))
            else:
                self.needles.extend(
                    (needle, len(needle), owners) for needle, owners in group.items()
                )
        self.zeros = zeros

    @staticmethod
    def kept(seen: dict[Any, Any], folded: bool, needle: bytes) -> list[int] | None:
        """A common anchor's places as the automaton's pass kept them (`AnchorIndex.place`), read
        exactly as `Places.occurrences` reads them: past what the file's budget still holds they
        refuse the file, and reading them spends it. None where the pass kept none."""
        starts = seen.get(("kept", folded, needle))
        if starts is None:
            return None
        budget = Search.budget(seen)
        if len(starts) > min(Places.MOST, budget[0]):
            raise Places.too_many()
        budget[0] -= len(starts)
        return list(starts)

    @staticmethod
    def occurrences(data: bytes, needle: bytes, budget: list[int] | None = None) -> list[int]:
        """Every offset `needle` begins at (`Places.occurrences`, which bounds them)."""
        return Places.occurrences(data, needle, budget)

    @staticmethod
    def budget(seen: dict[Any, Any]) -> list[int]:
        return Places.budget(seen)

    @staticmethod
    def too_many() -> Unbounded:
        return Places.too_many()


class _Hunt:
    """One string searched for in one piece of data."""

    #: Anchor occurrences of one part above which `_viable` is worth working out.
    BUSY: ClassVar[int] = 64
    #: Runs of one byte class `_viable` reads from each path, at most.
    SEGMENTS: ClassVar[int] = 16

    def __init__(
        self, search: Search, data: bytes, fixed: int | None, deadline: float | None
    ) -> None:
        self.s, self.data, self.fixed, self.deadline = search, data, fixed, deadline
        self.hits: dict[int, int] = {}
        self.waiting: list[list[list[int]]] = [
            [] for _ in search.parts
        ]  # per part: [off, len, chain]
        self.full = False
        f = search.flags
        self.nocase, self.dotall = "nocase" in f, "dotall" in f
        self.greedy = bool(f.get("greedy"))
        #: The data translated for each set of bytes a run may carry a thread list past.
        self.masks: dict[bytes, bytes] = {}
        #: Per (part, entries), where an anchor's runs can find anything (`_viable`), or None.
        self.feasible: dict[tuple[int, Any, Any], Any] = {}
        #: Per part, where each of its factors' runs starts, with its length (`_factor_near`).
        self.factor_runs: dict[int, list[tuple[list[int], int]]] = {}
        #: Per part, how many anchor occurrences the data has.
        self.busy: dict[int, int] = {}
        #: What the file may still hold of places to try (`Search.budget`); None outside a match.
        self.budget: list[int] | None = None
        #: Per text part, each candidate offset's match length, worked out for all of them at once
        #: (`anchoring.automaton.TextCheck`) before the events are run.
        self.texts: dict[int, dict[int, int]] = {}

    def run(self, events: list[Event]) -> list[tuple[int, int]]:
        """Checks each anchor occurrence, in the order `events` gives."""
        n = len(self.data)
        busy = self.busy
        for event in events:
            busy[event[3]] = busy.get(event[3], 0) + 1
        chained = self._chained(events)
        if chained is not None:
            for start, length in chained:
                if self.full:
                    break
                self._found(0, start, length, False)
            return sorted(self.hits.items())
        self._texts(events)
        self._run_events(events, n)
        return sorted(self.hits.items())

    #: Text-part candidates of one string above which they are checked all at once.
    BATCH: ClassVar[int] = 16

    def _texts(self, events: list[Event]) -> None:
        """Each text part's candidates checked in one call (natively where it can) instead of one
        `_check_text` comparison each; the answers `_check_text` then reads are the same."""
        parts, n = self.s.parts, len(self.data)
        wanted = {p for p, part in enumerate(parts) if part.text is not None and not part.fits}
        if not wanted:
            return
        offsets: dict[int, set[int]] = {}
        for e in events:
            if e[3] in wanted and e[5] < n:
                offsets.setdefault(e[3], set()).add(e[5])
        mode = TextCheck.mode(self.s.flags)
        for p, found in offsets.items():
            if len(found) >= _Hunt.BATCH:
                ordered = sorted(found)
                text = parts[p].text
                assert text is not None  # noqa: S101 - a text part
                self.texts[p] = dict(
                    zip(ordered, TextCheck.lengths(self.data, ordered, text, mode), strict=True)
                )

    def run_streamed(self, sources: list[Any]) -> list[tuple[int, int]] | None:
        """`run` over sorted event streams (`rule_engine.anchoring.stream`), pulling only until full; None
        where the string's matches are worked out from all its offsets at once (a chain)."""
        busy, total = Streams.busy(sources, _Hunt.BUSY + 1)
        self.busy = busy
        backward = self._chain_ready() if total > _Hunt.BUSY else None
        if backward is not None:
            chain, lag = self.s.parts[0].chain, Streams.lag(self.s)
            anchors = Streams.offsets(Streams.merged(sources), lag, len(self.data))
            for start, length in Streams.chained(
                chain, self.data, anchors, backward=backward, nocase=self.nocase,
                dotall=self.dotall, deadline=self.deadline,
            ):  # fmt: skip
                if self.full:
                    break
                self._found(0, start, length, False)
            return sorted(self.hits.items())
        self._run_events(Streams.merged(sources), len(self.data))
        return sorted(self.hits.items())

    def _run_events(self, events: Iterable[Event], n: int) -> None:
        for count, (_, _, _, part, anchor, offset) in enumerate(events):
            if count % 4096 == 0 and self.deadline is not None and time.monotonic() > self.deadline:
                raise TimeoutError("matching took longer than the time allowed")
            if self.full:
                break
            if offset >= n:
                continue
            if self.fixed is not None and part == 0 and offset != self.fixed:
                continue
            self._check(part, anchor, offset)

    def _chained(self, events: list[Event]) -> list[tuple[int, int]] | None:
        """Every match of a string that is one chain of class repeats (`rule_engine.chain`), worked out
        directly from its anchors' offsets when they occur often enough to make running them
        dear; None to run them as usual (as for an anchor outside the chain's first term)."""
        part = self.s.parts[0]
        backward = self._chain_ready() if len(events) > _Hunt.BUSY else None
        if backward is None or part.chain is None:
            return None
        n = len(self.data)
        offsets = sorted({e[5] for e in events if e[5] < n})
        return part.chain.matches(
            self.data,
            offsets,
            backward=backward,
            nocase=self.nocase,
            dotall=self.dotall,
            deadline=self.deadline,
        )

    def _chain_ready(self) -> bool | None:
        """Whether this string's matches come from its chain's matcher (`_chained`), and if so
        whether a match may start back over the first term (True or False); None when not."""
        parts, f = self.s.parts, self.s.flags
        part = parts[0]
        if len(parts) != 1 or part.chain is None:
            return None
        if f.get("plain") or "fullword" in f or self._widths() != [False] or self.fixed is not None:
            return None
        if any(anchor[2] != part.root_entry for anchor in part.anchors):
            return None
        return any(anchor[3] is not None for anchor in part.anchors)

    def starts(self, p: int, *, lazy: bool = False) -> Iterable[int]:
        """Where a part with no anchor is run from: every position, less those no run from
        there can do anything at. `lazy`: one at a time, holding none of them."""
        data = self.data
        along = self._along(p, lazy=lazy)
        if along is not None:
            return along
        ahead = self._ahead(p)
        if ahead is not None and lazy:
            # map, not a generator expression: compiled (mypyc), a generator expression passed on
            # becomes a list, which would hold every place at once
            return map(re.Match.start, ahead.finditer(data))
        if ahead is not None:
            found: list[int] = []
            most = min(Places.MOST, self.budget[0]) if self.budget is not None else Places.MOST
            for m in ahead.finditer(data):
                if len(found) >= most:
                    raise Search.too_many()
                found.append(m.start())
            if self.budget is not None:
                self.budget[0] -= len(found)
            return found
        firsts = self._firsts(p)
        if firsts is None and lazy:
            return iter(range(len(data)))
        if firsts is None:
            most = min(Places.MOST, self.budget[0]) if self.budget is not None else Places.MOST
            if len(data) > most:
                raise Search.too_many()
            if self.budget is not None:
                self.budget[0] -= len(data)
            return list(range(len(data)))
        mask = data.translate(bytes([1 if b in firsts else 0 for b in range(256)]))
        if lazy:
            return Streams.finds(mask, b"\x01")
        return Search.occurrences(mask, b"\x01", self.budget)

    def _along(
        self, p: int, segments: int | None = None, *, lazy: bool = False
    ) -> Iterable[int] | None:
        """The starts whose bytes follow a part's single starting path (`Along`), found a window
        at a time; None when the part starts along no path of two steps or more. With
        `segments`, only that many runs of one byte class from the path's start are used: fewer
        starts are ruled out, at a bounded cost."""
        part = self.s.parts[p]
        if self.s.flags.get("plain") or part.root_entry is None or self._widths() != [False]:
            return None
        steps = part.runners()[0].path(part.root_entry, nocase=self.nocase, dotall=self.dotall)
        if len(steps) < 2:
            return None
        if lazy:
            return Along.lazy(steps, self.data, segments)
        return Along.listed(steps, self.data, segments, self.budget)

    def _ahead(self, p: int) -> re.Pattern[bytes] | None:
        """For a part searched for only one byte wide, `Threads.prefilter` of its start."""
        part = self.s.parts[p]
        if self.s.flags.get("plain") or part.root_entry is None or self._widths() != [False]:
            return None
        return Threads(part.forward, part.memo).prefilter(
            part.root_entry, nocase=self.nocase, dotall=self.dotall
        )

    def _firsts(self, p: int) -> frozenset[int] | None:
        """The first bytes a run of part `p` from its start can do anything with, every width
        it runs at taken together; None when any byte can lead somewhere."""
        part = self.s.parts[p]
        f = self.s.flags
        if f.get("plain") or part.root_entry is None:
            return None
        out: set[int] = set()
        for wide in self._widths():
            firsts = Threads(part.forward, part.memo).first_reads(
                part.root_entry, wide=wide, nocase=self.nocase, dotall=self.dotall
            )
            if firsts is None:
                return None
            out |= firsts
        return frozenset(out)

    # -- checking one occurrence --------------------------------------------------

    def _factor_near(self, p: int, offset: int) -> bool:
        """Whether each run every match of part `p` holds (`Part.factors`) occurs where a match
        holding an anchor at `offset` could reach: no match reads more than `REACH` bytes either
        side of its anchor."""
        runs = self.factor_runs.get(p)
        if runs is None:
            runs = self.factor_runs[p] = [
                (found, length)
                for entry, length in self.s.parts[p].factors
                if (found := self._factor_runs(p, entry, length)) is not None
            ]
        for found, length in runs:
            i = bisect.bisect_left(found, offset - REACH)
            if i == len(found) or found[i] > offset + REACH - length:
                return False
        return True

    def _factor_runs(self, p: int, entry: int, length: int) -> list[int] | None:
        """Where a run of `length` bytes the term at `entry` reads starts in the data, in order;
        None when it cannot be told."""
        if self.s.flags.get("plain") or self._widths() != [False]:
            return None
        reads = (
            self.s.parts[p].runners()[0].first_reads(entry, nocase=self.nocase, dotall=self.dotall)
        )
        if reads is None:
            return None
        table = bytes([1 if b in reads else 0 for b in range(256)])
        run, covered = int.from_bytes(self.data.translate(table), "little"), 1
        while covered * 2 <= length:
            run &= run >> (8 * covered)
            covered *= 2
        if covered < length:
            run &= run >> (8 * (length - covered))
        if not run:
            return []
        return Search.occurrences(run.to_bytes(len(self.data), "little"), b"\x01", self.budget)

    def _viable(self, p: int, anchor: AnchorAt, offset: int) -> bool:
        """Whether the runs `_check` makes from an anchor at `offset` can find anything: the
        bytes from the anchor must follow its forward run's starting path, and the bytes before
        it its backward run's, each step's byte in its class (a byte outside the data is in
        none). Read at `offset` alone, the path worked out once for each pair of entries."""
        key = (p, anchor[2], anchor[3])
        reads = self.feasible.get(key, False)
        if reads is False:
            reads = self.feasible[key] = self._viable_reads(p, anchor[2], anchor[3])
        if reads is None:
            return True
        data, n = self.data, len(self.data)
        ahead, behind = reads
        for k, table in ahead:
            q = offset + k
            if q >= n or not table[data[q]]:
                return False
        for k, table in behind:
            q = offset - k - 1
            if q < 0 or not table[data[q]]:
                return False
        return True

    def _viable_reads(
        self, p: int, fwd: int | None, back: int | None
    ) -> tuple[list[tuple[int, bytes]], list[tuple[int, bytes]]] | None:
        """The steps `_viable` reads, as (how far from the anchor, the step's 0/1 class table),
        forwards and backwards; None when the part is not tested so (plain, wide, no forward
        entry, or paths of one step)."""
        part = self.s.parts[p]
        if self.s.flags.get("plain") or self._widths() != [False] or fwd is None:
            return None
        runners = part.runners()
        ahead = runners[0].path(fwd, nocase=self.nocase, dotall=self.dotall)
        behind = (
            []
            if back is None
            else runners[1].path(back, nocase=self.nocase, dotall=self.dotall, backwards=True)
        )
        if len(ahead) < 2 and len(behind) < 2:
            return None
        return (
            _Hunt._reads(ahead) if len(ahead) >= 2 else [],
            _Hunt._reads(behind) if len(behind) >= 2 else [],
        )

    @staticmethod
    def _reads(steps: list[bytes]) -> list[tuple[int, bytes]]:
        """The steps of a path a viability test reads: the first, then the runs of one byte class
        after it, `_Hunt.SEGMENTS` runs in all, each step of a run read."""
        out = [(0, steps[0])]
        i, used = 1, 1
        while i < len(steps) and used < _Hunt.SEGMENTS:
            used += 1
            same = 1
            while i + same < len(steps) and steps[i + same] == steps[i]:
                same += 1
            out += [(k, steps[k]) for k in range(i, i + same)]
            i += same
        return out

    def _check(self, p: int, anchor: AnchorAt, offset: int) -> None:
        part = self.s.parts[p]
        if part.text is not None:
            self._check_text(p, part, anchor, offset)
            return
        f = self.s.flags
        fwd, back = anchor[2], anchor[3]
        if fwd is None:
            return
        if (
            part.heavy
            and self.busy.get(p, 0) > _Hunt.BUSY
            and not (self._viable(p, anchor, offset) and self._factor_near(p, offset))
        ):
            return  # a run from the anchor dies on the bytes around it, or no match fits there
        for wide in self._widths():
            if f.get("plain"):
                length = Lanes(part.forward).run(fwd, self.data, offset, deadline=self.deadline)
            elif not wide and not part.can_start(fwd, self.data, offset, self.nocase, self.dotall):
                length = -1  # every thread dies within the gate's reach having matched nothing
            else:
                length = part.runners()[0].run(
                    fwd,
                    self.data,
                    offset,
                    wide=wide,
                    nocase=self.nocase,
                    dotall=self.dotall,
                    masks=self.masks,
                )
            if length != -1 and back is not None:

                def found(start: int, before: int, length: int = length, wide: bool = wide) -> None:
                    self._found(p, start, before + length, wide)

                if f.get("plain"):
                    Lanes(part.backward).run(
                        back, self.data, offset, backwards=True, every=found, deadline=self.deadline
                    )
                else:
                    part.runners()[1].run(
                        back, self.data, offset, backwards=True, wide=wide, nocase=self.nocase,
                        dotall=self.dotall, every=found, masks=self.masks,
                    )  # fmt: skip
            elif length >= 0:
                # with nothing to run backwards the match is taken as it stands, and its
                # whole-word test is the one-byte one even when the run read wide text
                self._found(p, offset, length, False)

    def _widths(self) -> list[bool]:
        f = self.s.flags
        out = []
        if "ascii" in f or "base64" in f or "base64wide" in f:
            out.append(False)
        if "wide" in f:
            out.append(True)
        return out

    def _check_text(self, p: int, part: Part, anchor: AnchorAt, offset: int) -> None:
        f = self.s.flags
        text = part.text
        assert text is not None  # noqa: S101 - a text part
        data, n = self.data, len(self.data)
        if part.fits:
            length = len(anchor[0]) + anchor[1]
        elif p in self.texts:
            length = self.texts[p].get(offset, 0)
        elif "nocase" in f:
            length = 0
            if "ascii" in f:
                length = _Compare.same(data, offset, text, Bytes.LOWER)
            if "wide" in f and length == 0:
                length = _Compare.same_wide(data, offset, text, Bytes.LOWER)
        else:
            length = 0
            if "ascii" in f:
                length = _Compare.same(data, offset, text, None)
            if "wide" in f and length == 0:
                length = _Compare.same_wide(data, offset, text, None)
            if "xor" in f and length == 0:
                if "wide" in f:
                    length = _Compare.xored_wide(data, offset, text)
                if length == 0:
                    length = _Compare.xored(data, offset, text)
        if length == 0 or offset >= n:
            return
        self._found(p, offset, length, length == len(text) * 2)

    # -- recording a match ---------------------------------------------------------

    def _found(self, p: int, start: int, length: int, wide: bool) -> None:
        if "fullword" in self.s.flags and not _Compare.whole(self.data, start, length, wide):
            return
        if len(self.s.parts) > 1:
            self._link(p, start, length)
            return
        self._record(start, length, replace=self.greedy)

    def _record(self, start: int, length: int, *, replace: bool) -> None:
        if start in self.hits:
            if replace:
                self.hits[start] = length
            return
        if len(self.hits) >= MAX_HITS:
            self.full = True
            return
        self.hits[start] = length

    def _link(self, p: int, start: int, length: int) -> None:
        """A match of part `p` of a linked string: kept until the parts after it are found at
        the right distance, then the whole string recorded from its first part's start."""
        parts, waiting = self.s.parts, self.waiting
        add = p == 0
        if not add:
            lo, hi = parts[p].gap
            lowest = waiting[p][0][0] if waiting[p] else start
            before = waiting[p - 1]
            k = 0
            while k < len(before):
                m = before[k]
                end = m[0] + m[1]
                if end + hi < lowest:
                    del before[k]
                    continue
                if end + hi >= start and end + lo <= start:
                    add = True
                    break
                k += 1
        if not add:
            return
        if p == len(parts) - 1:
            lo, hi = parts[p].gap
            for m in waiting[p - 1]:
                end = m[0] + m[1]
                if end + hi >= start and end + lo <= start:
                    self._lengthen(p - 1, m, 1)
            head = waiting[0]
            k = 0
            while k < len(head):
                m = head[k]
                if m[2] == p:
                    del head[k]
                    self._record(m[0], start - m[0] + length, replace=False)
                    continue
                k += 1
            return
        group = waiting[p]
        if any(m[0] == start for m in group):
            return
        if len(group) >= MAX_HITS:
            self.full = True
            return
        k = len(group)
        while k > 0 and group[k - 1][0] > start:
            k -= 1
        group.insert(k, [start, length, 0])

    def _lengthen(self, p: int, m: list[int], links: int) -> None:
        """Marks how many parts after `m` are found at the right distances, back to the head."""
        if m[2] == links:
            return
        m[2] = links
        if p == 0:
            return
        lo, hi = self.s.parts[p].gap
        for other in self.waiting[p - 1]:
            end = other[0] + other[1]
            if end + hi >= m[0] and end + lo <= m[0]:
                self._lengthen(p - 1, other, links + 1)


__all__ = ["MAX_HITS", "Search", "_Hunt"]
