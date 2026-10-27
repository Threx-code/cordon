"""cordon-rule string search: where each string of a rule matches in the data.

A declared string becomes a `Search`: one or more `Part`s (a hex pattern with a long jump is cut
into linked parts at the jump, each found on its own and joined when the distance fits), each with
the anchors its search looks for. The search walks the data once per anchor; every place an
anchor occurs is checked in turn -- text compared, patterns run forwards from the anchor and
backwards from it for every start the match can have -- in the order of where the anchor ends,
longer anchors first, later-declared anchors first.
"""

from __future__ import annotations

import re
import time
from collections.abc import Iterator
from typing import Any, ClassVar

from cordon_scanner.detect.binary.rule_pattern import (
    GAP,
    LINK_GAP,
    LIT,
    SEQ,
    Anchor,
    Anchors,
    Bytes,
    HexReader,
    Lanes,
    PatternError,
    Program,
    RegexReader,
    Term,
    Threads,
)

#: An anchor as searched for: its bytes, how far into the string it starts, and where the forward
#: and backward layouts start from it (None for text).
AnchorAt = tuple[bytes, int, int | None, int | None]
#: An anchor occurrence, ordered as it is checked: (end, -length, -order, part, anchor, offset).
Event = tuple[int, int, int, int, AnchorAt, int]

#: The most matches one string records; past this it is not searched further in that data.
MAX_HITS = 1_000_000


class Part:
    """One piece of a string: plain bytes (`text`) or a pattern (`forward`/`backward` layouts),
    and the anchors that find it. `gap` is the (least, most) distance from the previous part."""

    def __init__(self) -> None:
        self.text: bytes | None = None
        self.forward: list[tuple[int, ...]] = []
        self.backward: list[tuple[int, ...]] = []
        self.root_entry: int | None = None
        self.anchors: list[AnchorAt] = []
        self.fits = False  # text short enough that an anchor occurrence is the match
        #: Steps the layouts have taken, kept across runs and files (`rule_pattern.Memo`).
        self.memo: dict[tuple[bool, ...], Any] = {}
        self.gap = (0, 0)


class Search:
    """A string, ready to be searched for. `flags` holds the modifiers that apply: nocase, wide,
    ascii, fullword, xor (lo, hi), base64, base64wide, dotall, greedy, plain."""

    METACHARS: ClassVar[bytes] = b"\\^$|()[]*?{,.+}"

    def __init__(self, kind: str, value: Any, modifiers: dict[str, Any]) -> None:
        self.flags: dict[str, Any] = dict(modifiers)
        self.parts: list[Part] = []
        #: The anchors to look for, by distinct bytes (`_index`), and the parts with none.
        self.needles: list[tuple[bytes, int, list[tuple[int, int, AnchorAt]]]] | None = None
        self.zeros: list[tuple[int, int, AnchorAt]] = []
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
        if root.kind == SEQ and all(k.kind == LIT for k in root.kids):
            return bytes(k.value for k in root.kids)
        return None

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
            out += bytes(alphabet[n >> s & 63] for s in (18, 12, 6, 0))
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
        return b"".join(bytes([b, 0]) for b in data)

    # -- searching ---------------------------------------------------------------

    def find(
        self,
        data: bytes,
        fixed: int | None = None,
        deadline: float | None = None,
        seen: dict[bytes, list[int]] | None = None,
    ) -> list[tuple[int, int]]:
        """(offset, length) of each match, by offset. With `fixed`, only a match there counts.
        `seen` holds where each anchor occurs in `data`, shared by every string searched there,
        so each distinct anchor is looked for once per piece of data."""
        if self.needles is None:
            self._index()
        assert self.needles is not None  # noqa: S101 - set by _index
        seen = {} if seen is None else seen
        events: list[Event] = []
        for needle, length, owners in self.needles:
            starts = seen.get(needle)
            if starts is None:
                starts = seen[needle] = Search.occurrences(data, needle)
            if not starts:
                continue
            for order, p, anchor in owners:
                back = length + anchor[1]
                events.extend(
                    (s + length, -length, -order, p, anchor, s + length - back)
                    for s in starts
                    if back <= s + length
                )
        hunt = _Hunt(self, data, fixed, deadline)
        for order, p, anchor in self.zeros:
            events.extend((at, 0, -order, p, anchor, at) for at in hunt.starts(p))
        if not events:
            return []
        events.sort(key=lambda e: (e[0], e[1], e[2]))
        return hunt.run(events)

    def _index(self) -> None:
        """The anchors of every part, by distinct bytes, numbered in the order they are checked
        when two end at the same place (a later one first)."""
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
        self.needles = [(needle, len(needle), owners) for needle, owners in table.items()]
        self.zeros = zeros

    @staticmethod
    def occurrences(data: bytes, needle: bytes) -> list[int]:
        """Every offset `needle` begins at, overlapping ones included."""
        out = []
        at = data.find(needle)
        while at >= 0:
            out.append(at)
            at = data.find(needle, at + 1)
        return out


class _Hunt:
    """One string searched for in one piece of data."""

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

    def run(self, events: list[Event]) -> list[tuple[int, int]]:
        """Checks each anchor occurrence, in the order `events` gives."""
        n = len(self.data)
        for count, (_, _, _, part, anchor, offset) in enumerate(events):
            if count % 4096 == 0 and self.deadline is not None and time.monotonic() > self.deadline:
                raise TimeoutError("matching took longer than the time allowed")
            if offset >= n or self.full:
                continue
            if self.fixed is not None and part == 0 and offset != self.fixed:
                continue
            self._check(part, anchor, offset)
        return sorted(self.hits.items())

    def starts(self, p: int) -> list[int]:
        """Where a part with no anchor is run from: every position, less those no run from
        there can do anything at."""
        data = self.data
        ahead = self._ahead(p)
        if ahead is not None:
            return [m.start() for m in ahead.finditer(data)]
        firsts = self._firsts(p)
        if firsts is None:
            return list(range(len(data)))
        mask = data.translate(bytes(1 if b in firsts else 0 for b in range(256)))
        return Search.occurrences(mask, b"\x01")

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

    def _check(self, p: int, anchor: AnchorAt, offset: int) -> None:
        part = self.s.parts[p]
        if part.text is not None:
            self._check_text(p, part, anchor, offset)
            return
        f = self.s.flags
        fwd, back = anchor[2], anchor[3]
        if fwd is None:
            return
        for wide in self._widths():
            if f.get("plain"):
                length = Lanes(part.forward).run(fwd, self.data, offset)
            else:
                length = Threads(part.forward, part.memo).run(
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
                    Lanes(part.backward).run(back, self.data, offset, backwards=True, every=found)
                else:
                    Threads(part.backward, part.memo).run(
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


class _Compare:
    """Text compared at an offset: as is, every other byte zero (wide), or xored with a key."""

    @staticmethod
    def same(data: bytes, at: int, text: bytes, fold: bytes | None) -> int:
        if len(data) - at < len(text):
            return 0
        piece = data[at : at + len(text)]
        if fold is not None:
            return len(text) if piece.translate(fold) == text.translate(fold) else 0
        return len(text) if piece == text else 0

    @staticmethod
    def same_wide(data: bytes, at: int, text: bytes, fold: bytes | None) -> int:
        if len(data) - at < 2 * len(text):
            return 0
        piece = data[at : at + 2 * len(text)]
        if piece[1::2].count(0) != len(text):
            return 0
        low = piece[0::2]
        if fold is not None:
            return 2 * len(text) if low.translate(fold) == text.translate(fold) else 0
        return 2 * len(text) if low == text else 0

    @staticmethod
    def xored(data: bytes, at: int, text: bytes) -> int:
        if len(data) - at < len(text):
            return 0
        key = data[at] ^ text[0]
        piece = data[at : at + len(text)]
        return len(text) if all(a == b ^ key for a, b in zip(piece, text, strict=True)) else 0

    @staticmethod
    def xored_wide(data: bytes, at: int, text: bytes) -> int:
        if len(data) - at < 2 * len(text):
            return 0
        key = data[at] ^ text[0]
        for i, b in enumerate(text):
            if data[at + 2 * i] != b ^ key or data[at + 2 * i + 1] ^ key != 0:
                return 0
        return 2 * len(text)

    @staticmethod
    def whole(data: bytes, start: int, length: int, wide: bool) -> bool:
        """No letter or digit joins the match on either side (a zero byte between, if wide)."""
        alnum = Bytes.ALNUM
        n = len(data)
        if wide:
            if start >= 2 and data[start - 1] == 0 and data[start - 2] in alnum:
                return False
            end = start + length
            return not (end + 1 < n and data[end + 1] == 0 and data[end] in alnum)
        if start >= 1 and data[start - 1] in alnum:
            return False
        return not (start + length < n and data[start + length] in alnum)


class Matcher:
    """A condition's `matches`: whether a regular expression matches anywhere in a text."""

    def __init__(self, source: bytes, marks: str) -> None:
        reader = RegexReader(source)
        root = reader.read()
        program = Program(root, backwards=False)
        self.ops, self.entry = program.ops, program.entry
        self.nocase, self.dotall = "i" in marks, "s" in marks
        self.memo: dict[tuple[bool, ...], Any] = {}

    def run(self, text: bytes) -> int:
        """Where the match the run settles on ends, counted from the text's start; -1 for none."""
        return Threads(self.ops, self.memo).run(
            0, text, 0, nocase=self.nocase, dotall=self.dotall, scan=True
        )

    def test(self, text: bytes) -> bool:
        return self.run(text) >= 0
