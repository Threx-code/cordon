"""Every anchor of a rule set, looked for once per piece of data (`AnchorIndex`): which strings have
one that occurs there, whether each string's required literal runs occur, and where the anchors of
the strings that will be searched begin, all from one pass per automaton (`rule_engine.automaton`)."""

from __future__ import annotations

from typing import Any

from cordon_scanner.detect.binary.rule_engine.automaton import Automaton
from cordon_scanner.detect.binary.rule_engine.scan import Search


class AnchorIndex:
    """Every anchor of a rule set, looked for once per piece of data: which strings have one
    that occurs there. Only those (and strings with no anchor, which run everywhere) need
    searching; every other string has no match without being looked at."""

    def __init__(self, searches: list[Search]) -> None:
        self.exact: dict[bytes, list[int]] = {}
        self.folded: dict[bytes, list[int]] = {}
        self.always: set[int] = set()
        for i, s in enumerate(searches):
            if s.needles is None:
                s._index()
            for needle, _, _ in s.needles or ():
                self.exact.setdefault(needle, []).append(i)
            for folded, _, _ in s.folds:
                self.folded.setdefault(folded, []).append(i)
            if s.zeros:
                self.always.add(i)
        # the literal runs `Search._holds_required` asks about ride in the same automata, so one
        # pass answers them too: plain runs as they are, a `nocase` string's runs lowered
        self.runs: dict[bool, dict[bytes, list[bytes]]] = {False: {}, True: {}}
        for s in searches:
            f = s.flags
            if "wide" in f or "xor" in f or "base64" in f or "base64wide" in f:
                continue
            nocase = "nocase" in f
            for part in s.parts:
                for run in part.required:
                    held = self.runs[nocase].setdefault(run.lower() if nocase else run, [])
                    if run not in held:
                        held.append(run)
        self.exact_keys, self.folded_keys = list(self.exact), list(self.folded)
        self.exact_all = self.exact_keys + [r for r in self.runs[False] if r not in self.exact]
        self.folded_all = self.folded_keys + [r for r in self.runs[True] if r not in self.folded]
        self.exact_id = {n: i for i, n in enumerate(self.exact_all)}
        self.folded_id = {n: i for i, n in enumerate(self.folded_all)}
        self.exact_set = Automaton(self.exact_all)
        self.folded_set = Automaton(self.folded_all, fold=True)

    def live(self, data: bytes, seen: dict[Any, Any]) -> set[int]:
        """The strings with an anchor in `data`. (`seen` is the data's shared record, which
        `Search.find` fills with where each anchor occurs.)"""
        out = set(self.always)
        # whether each anchor occurs at all, in one pass; where, only for a string that is
        # searched (`Search.find`), and not even there for an anchor its gate reads in one pass
        found = {self.exact_all[i] for i in self.exact_set.present(data)}
        for needle in found:
            if needle in self.exact:
                out.update(self.exact[needle])
        AnchorIndex.held(seen, self.runs[False], found, folded=False)
        if self.folded_all:
            lowered = AnchorIndex.lowered(data, seen, self.folded_set)
            found = {self.folded_all[i] for i in self.folded_set.present(data, lowered)}
            for needle in found:
                if needle in self.folded:
                    out.update(self.folded[needle])
            AnchorIndex.held(seen, self.runs[True], found, folded=True)
        return out

    @staticmethod
    def held(
        seen: dict[Any, Any], runs: dict[bytes, list[bytes]], found: set[bytes], *, folded: bool
    ) -> None:
        """Whether each required run occurs, kept as `Search._holds_required` keeps it."""
        for run, originals in runs.items():
            for original in originals:
                seen[("holds", folded, original)] = run in found

    @staticmethod
    def lowered(data: bytes, seen: dict[Any, Any], automaton: Automaton) -> bytes | None:
        """The data lowered, shared through `seen`, where the reading needs it (not natively)."""
        if automaton.native:
            return None
        lowered = seen.get(("lowered",))
        if lowered is None:
            lowered = seen[("lowered",)] = data.lower()
        return lowered

    @staticmethod
    def afford(seen: dict[Any, Any], starts: list[int]) -> bool:
        """Whether the file's budget holds `starts`, spending it if so."""
        budget = Search.budget(seen)
        if len(starts) > budget[0]:
            return False
        budget[0] -= len(starts)
        return True

    def prefill(self, data: bytes, seen: dict[Any, Any], searches: list[Search]) -> None:
        """Where each anchor of `searches` begins, found in one pass per automaton and kept in
        `seen` the way `Search.find` keeps what it finds: an anchor occurring more than
        `Search.GATED` times is left for `Search.find`, which reads a common anchor its own way."""
        exact = {self.exact_id[n] for s in searches for n, _, _ in s.needles or () if n not in seen}
        for i, starts in self.exact_set.positions(data, exact, Search.GATED).items():
            if starts is not None and AnchorIndex.afford(seen, starts):
                seen[self.exact_keys[i]] = starts
        folded = {
            self.folded_id[f] for s in searches for f, _, _ in s.folds if ("folded", f) not in seen
        }
        if folded:
            lowered = AnchorIndex.lowered(data, seen, self.folded_set)
            for i, starts in self.folded_set.positions(data, folded, Search.GATED, lowered).items():
                if starts is not None and AnchorIndex.afford(seen, starts):
                    seen[("folded", self.folded_keys[i])] = starts


__all__ = ["AnchorIndex"]
