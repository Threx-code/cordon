"""One pass over a piece of data for many byte anchors: which occur, and where.

`Automaton` is the native one (`cordon_scanner._native._anchors`, an Aho-Corasick automaton in C)
when the extension is importable, else the pure-Python one: `NeedleSet` for which occur and
`bytes.find` for where, the reading this rule engine always had. Both give the same answers on
every input, which test_native_anchors holds them to; `Automaton.NATIVE` and `Automaton.WHY` say
which is in use and why, and the rule-file status and `--version` report it.

    Automaton(needles, fold=False)   distinct byte needles (an empty one occurs everywhere)
    .present(data) -> list[int]      the ids (positions in `needles`) occurring, ascending
    .positions(data, ids, cap)       {id: start offsets ascending, overlapping ones included,
                                      or None where more than `cap` occur}

With `fold`, the data is read lowered by ASCII (bytes.lower's rule) and the needles as given (the
caller lowers them). An automaton is never pickled: a pack cache keeps the rules, and the anchor
index builds its automata on first use after a load.
"""

from __future__ import annotations

import functools
import hashlib
import os
import time
from array import array
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any, ClassVar

from cordon_scanner.detect.binary.rule_engine.anchoring.needles import NeedleSet
from cordon_scanner.detect.binary.rule_engine.hits import Hits
from cordon_scanner.detect.binary.rule_engine.pattern import Bytes, Op
from cordon_scanner.detect.binary.rule_engine.threads import REACH


class Native:
    """The extension, or why it is not in use."""

    @staticmethod
    def load() -> tuple[Any, str]:
        if os.environ.get("CORDON_NO_NATIVE"):
            return None, "the native anchor matcher is turned off (CORDON_NO_NATIVE)"
        try:
            from cordon_scanner._native import _anchors  # type: ignore[attr-defined]
        except ImportError as exc:
            return None, f"the native anchor matcher is not built ({exc})"
        return _anchors, "native"


class Automaton:
    MODULE, WHY = Native.load()
    NATIVE: ClassVar[bool] = MODULE is not None

    #: The rule-engine modules a wheel may hold compiled (mypyc), each with its Python twin.
    COMPILED: ClassVar[tuple[str, ...]] = ("scan", "threads")
    #: What the build writes beside the compiled modules: the compiler and its version.
    ENGINE_BUILD: ClassVar[str] = "ENGINE_BUILD"

    @staticmethod
    def status() -> str:
        """Which anchor matcher runs, for the rule-file status and `--version`: the native one with
        the sha256 of the binary loaded, or the Python one and why; then which engine modules run
        compiled (`engine`)."""
        if Automaton.MODULE is None:
            matcher = f"Python anchor matcher ({Automaton.WHY})"
        else:
            matcher = f"native anchor matcher (sha256 {Automaton.digest()})"
        return f"{matcher}; {Automaton.engine()}"

    @staticmethod
    def engine() -> str:
        """ "engine modules compiled: scan, threads (mypyc 2.4.0)", or "engine: Python". A compiled
        module is found before its source at import, whatever CORDON_NO_NATIVE says, so this is
        read from what was loaded -- a module whose file is an extension, as
        `PackCache.build_kind` reads it -- not from a setting."""
        import importlib
        import sys

        prefix = "cordon_scanner.detect.binary.rule_engine."
        compiled = []
        for name in Automaton.COMPILED:
            module = sys.modules.get(prefix + name) or importlib.import_module(prefix + name)
            if str(getattr(module, "__file__", "")).endswith((".so", ".pyd")):
                compiled.append(name)
        if not compiled:
            return "engine: Python"
        from cordon_scanner.foundation.paths import PackagePaths

        stamp = PackagePaths.root() / "_native" / Automaton.ENGINE_BUILD
        try:
            built = stamp.read_text(encoding="utf-8").strip()[:64] or "mypyc"
        except OSError:
            built = "mypyc"
        return f"engine modules compiled: {', '.join(compiled)} ({built})"

    @staticmethod
    @functools.cache
    def digest() -> str:
        """The loaded extension's sha256, worked out once, when first asked for: the binary does
        not change while the process runs."""
        path = getattr(Automaton.MODULE, "__file__", None)
        try:
            return hashlib.sha256(Path(str(path)).read_bytes()).hexdigest()
        except (OSError, TypeError):
            return "unreadable"

    __slots__ = ("_c", "_ids", "_set", "empty", "fold", "needles")

    def __init__(
        self, needles: Sequence[bytes], *, fold: bool = False, native: bool | None = None
    ) -> None:
        self.needles, self.fold = list(needles), fold
        if len(set(self.needles)) != len(self.needles):
            raise ValueError("a needle is given twice")
        self.empty = [i for i, n in enumerate(self.needles) if not n]
        self._ids = [i for i, n in enumerate(self.needles) if n]
        # below NeedleSet.FEW needles, `needle in data` each (memchr in C) beats any automaton walk
        use = (
            (Automaton.NATIVE and len(self._ids) >= NeedleSet.FEW)
            if native is None
            else native and Automaton.NATIVE
        )
        self._c = (
            Automaton.MODULE.Automaton([self.needles[i] for i in self._ids], fold=fold)
            if use
            else None
        )
        self._set = None if use else NeedleSet(self.needles)

    @property
    def native(self) -> bool:
        return self._c is not None

    @property
    def nbytes(self) -> int:
        return int(self._c.nbytes) if self._c is not None else 0

    def _view(self, data: bytes) -> bytes:
        return data.lower() if self.fold else data

    def present(self, data: bytes, lowered: bytes | None = None) -> list[int]:
        """`lowered`, with `fold`: the data already lowered (the Python reading uses it)."""
        if self._c is not None:
            return sorted([self._ids[i] for i in self._c.present(data)] + self.empty)
        assert self._set is not None  # noqa: S101 - set when not native
        found = self._set.present(
            lowered if self.fold and lowered is not None else self._view(data)
        )
        return [i for i, n in enumerate(self.needles) if n in found]

    def positions(
        self, data: bytes, ids: Iterable[int], cap: int, lowered: bytes | None = None
    ) -> dict[int, list[int] | None]:
        wanted = sorted(set(ids))
        out: dict[int, list[int] | None] = {}
        for i in wanted:
            if not self.needles[i]:
                out[i] = list(range(len(data) + 1)) if len(data) + 1 <= cap else None
        rest = [i for i in wanted if self.needles[i]]
        if self._c is not None:
            back = {n: k for k, n in enumerate(self._ids)}
            got = self._c.positions(data, [back[i] for i in rest], cap)
            for k, raw in got.items():
                out[self._ids[k]] = None if raw is None else list(memoryview(raw).cast("q"))
            return out
        view = lowered if self.fold and lowered is not None else self._view(data)
        for i in rest:
            starts = Automaton.occurrences(view, self.needles[i], cap)
            out[i] = starts
        return out

    @staticmethod
    def occurrences(data: bytes, needle: bytes, cap: int) -> list[int] | None:
        """Every offset `needle` begins at, overlapping ones included; None past `cap`."""
        found: list[int] = []
        at = data.find(needle)
        while at >= 0:
            if len(found) >= cap:
                return None
            found.append(at)
            at = data.find(needle, at + 1)
        return found


class TextCheck:
    """Each candidate offset's text match length (0 for none) for one text part, as
    `scan._Hunt._check_text` reads it: natively (`_anchors.check_text`) when the extension is in use,
    else this module's Python twin, the same comparisons one offset at a time."""

    ASCII, WIDE, NOCASE, XOR = 1, 2, 4, 8

    @staticmethod
    def mode(flags: dict[str, Any]) -> int:
        return (
            (TextCheck.ASCII if "ascii" in flags else 0) | (TextCheck.WIDE if "wide" in flags else 0)
            | (TextCheck.NOCASE if "nocase" in flags else 0) | (TextCheck.XOR if "xor" in flags else 0)
        )  # fmt: skip

    @staticmethod
    def lengths(
        data: bytes, offsets: list[int], text: bytes, mode: int, *, native: bool | None = None
    ) -> list[int]:
        if (Automaton.NATIVE if native is None else native and Automaton.NATIVE) and offsets:
            raw = Automaton.MODULE.check_text(data, array("q", offsets).tobytes(), text, mode)
            return list(memoryview(raw).cast("q"))
        return [TextCheck.at(data, q, text, mode) for q in offsets]

    @staticmethod
    def at(data: bytes, q: int, text: bytes, mode: int) -> int:
        if q < 0 or q >= len(data):
            return 0
        length = 0
        if mode & TextCheck.NOCASE:
            if mode & TextCheck.ASCII:
                length = Compare.same(data, q, text, Bytes.LOWER)
            if mode & TextCheck.WIDE and length == 0:
                length = Compare.same_wide(data, q, text, Bytes.LOWER)
            return length
        if mode & TextCheck.ASCII:
            length = Compare.same(data, q, text, None)
        if mode & TextCheck.WIDE and length == 0:
            length = Compare.same_wide(data, q, text, None)
        if mode & TextCheck.XOR and length == 0:
            if mode & TextCheck.WIDE:
                length = Compare.xored_wide(data, q, text)
            if length == 0:
                length = Compare.xored(data, q, text)
        return length


class Compare:
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


class TextFind:
    """A text string's whole find in one native call (`_anchors.text_hits`): its anchors'
    occurrences in, its matches (start, length) out, as `scan._Hunt` finds them -- the events in
    the hunt's order, the text checked at each, `fullword`, the first match at a start kept (or,
    `greedy`, the last), and the stop at `MAX_HITS`. A case-folded anchor's occurrences are grouped
    by how the data spells them there, each spelling with its owners (no two groups can tie on the
    hunt's key: a tie needs one owner, so one anchor). Only for a string of one text part with no
    base64 or anchorless part; every other string, and every string where the extension is not in
    use, is found by the hunt itself, which is this one's twin."""

    FITS, FULLWORD, GREEDY = 1, 2, 4

    @staticmethod
    def usable(search: Any) -> bool:
        if not Automaton.NATIVE or len(search.parts) != 1 or search.parts[0].text is None:
            return False
        f = search.flags
        return not (search.zeros or "base64" in f or "base64wide" in f)

    @staticmethod
    def hits(
        search: Any,
        data: bytes,
        owners: list[tuple[list[int], int, int, int, int]],
        fixed: int | None,
        max_hits: int,
        deadline: float | None = None,
    ) -> Hits:
        part, f = search.parts[0], search.flags
        flags = (
            (TextFind.FITS if part.fits else 0) | (TextFind.FULLWORD if "fullword" in f else 0)
            | (TextFind.GREEDY if f.get("greedy") else 0)
        )  # fmt: skip
        starts, lengths = Automaton.MODULE.text_hits(
            data,
            owners,
            part.text,
            TextCheck.mode(f),
            flags,
            max_hits,
            -1 if fixed is None else fixed,
            -1.0 if deadline is None else max(deadline - time.monotonic(), 0.0),
        )
        out = Hits()
        out.starts.frombytes(starts)
        out.lengths.frombytes(lengths)
        return out


class HexFind:
    """A plain hex string's whole find in one native call (`_anchors.hex_hits`): its anchors'
    occurrences in, its matches out, as `scan._Hunt` finds them with `threads.Lanes` -- the
    events in the hunt's order, the forward layout run from each anchor's forward entry (the
    shortest match), the backward one from its backward entry to every start it reaches (so a
    pattern of repeated bytes, where an anchor may sit at several places, has each tried), the
    first match at a start kept, and the stop at `MAX_HITS`. Only for a string of one plain part
    (no alternatives) with no heavy jump or repeat, no anchorless part and only the instructions
    Lanes reads; every other string, and every string where the extension is not in use, is found
    by the hunt itself, which is this one's twin."""

    FULLWORD: ClassVar[int] = 2
    RUNS: ClassVar[frozenset[int]] = frozenset(
        {Op.BYTE, Op.NOT_BYTE, Op.MASK, Op.NOT_MASK, Op.ANY, Op.SKIP, Op.DONE}
    )

    @staticmethod
    def layouts(search: Any) -> tuple[bytes, bytes] | None:
        """The part's forward and backward layouts as int64 triples, worked out once; None when
        the string is not found so."""
        if search.hex_layouts is None:
            search.hex_layouts = HexFind._encoded(search) or False
        return search.hex_layouts or None

    @staticmethod
    def _encoded(search: Any) -> tuple[bytes, bytes] | None:
        if not Automaton.NATIVE or len(search.parts) != 1 or search.zeros or search.folds:
            return None
        part = search.parts[0]
        if part.text is not None or not search.flags.get("plain") or part.heavy or part.chain:
            return None
        out = []
        for ops in (part.forward, part.backward):
            if any(op[0] not in HexFind.RUNS for op in ops):
                return None
            flat = array("q")
            for op in ops:
                flat.extend((*tuple(op), 0, 0)[:3])
            out.append(flat.tobytes())
        return out[0], out[1]

    @staticmethod
    def hits(
        search: Any, data: bytes, seen: dict[Any, Any], fixed: int | None, max_hits: int,
        deadline: float | None,
    ) -> Hits:  # fmt: skip
        forward, backward = search.hex_layouts
        owners = []
        for needle, length, holders in search.needles:
            starts = seen.get(needle)
            if starts is None:
                starts = seen[needle] = search.occurrences(data, needle, search.budget(seen))
            owners += [
                (starts, length, length + a[1], order, -1 if a[2] is None else a[2],
                 -1 if a[3] is None else a[3])
                for order, _, a in holders
            ]  # fmt: skip
        starts, lengths = Automaton.MODULE.hex_hits(
            data, owners, forward, backward, REACH,
            HexFind.FULLWORD if "fullword" in search.flags else 0, max_hits,
            -1 if fixed is None else fixed,
            -1.0 if deadline is None else max(deadline - time.monotonic(), 0.0),
        )  # fmt: skip
        out = Hits()
        out.starts.frombytes(starts)
        out.lengths.frombytes(lengths)
        return out


__all__ = ["Automaton", "Compare", "HexFind", "TextCheck", "TextFind"]
