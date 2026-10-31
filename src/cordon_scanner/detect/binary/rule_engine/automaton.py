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
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any, ClassVar

from cordon_scanner.detect.binary.rule_engine.needles import NeedleSet


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

    @staticmethod
    def status() -> str:
        """Which anchor matcher runs, for the rule-file status and `--version`: the native one with
        the sha256 of the binary loaded, or the Python one and why."""
        if Automaton.MODULE is None:
            return f"Python anchor matcher ({Automaton.WHY})"
        return f"native anchor matcher (sha256 {Automaton.digest()})"

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


__all__ = ["Automaton"]
