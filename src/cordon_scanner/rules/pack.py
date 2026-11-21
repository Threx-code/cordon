"""What a rule pack compiles to: each rule's matching strategy (a regex, literals, a structural query) resolved at load time, the compiled rule, and the pack that holds them."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.foundation.capabilities import Capability, MatchKind
from cordon_scanner.foundation.errors import RulePackError, UnsafePatternError
from cordon_scanner.foundation.rule_model import Rule
from cordon_scanner.foundation.text.literals import LiteralGate
from cordon_scanner.rules.anchored import AnchoredSearch, Plan
from cordon_scanner.rules.patterns import PatternCompiler

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping


class RuleOverBudget(TimeoutError):
    """One rule's regex spent more CPU on one file than its budget (S7: a crafted file driving a
    matcher to super-linear time). A TimeoutError, so the detector runner reports it as
    OPERATIONAL.FILE.TIMEOUT, a gap: the file's checks did not finish, and it never passes."""

    def __init__(self, rule_id: str, spent: float, budget: float) -> None:
        super().__init__(
            f"rule {rule_id or '<unnamed>'} spent {spent:.2f}s of CPU, over its {budget:.2f}s "
            "budget for this file"
        )
        self.rule_id, self.spent, self.budget = rule_id, spent, budget


@dataclass(frozen=True, slots=True)
class CompiledMatch:
    """A rule's matching strategy, resolved at load time."""

    kind: MatchKind
    regex: re.Pattern[bytes] | None = None
    literals: tuple[bytes, ...] = ()
    capability: Capability | None = None
    scope: str = "file"
    proximity: int = 0
    """How many lines may separate the capabilities a composite requires.

    Zero means the whole file, which is what every composite meant before
    this existed. That is right for a fifty-line install script and wrong
    for Node's Makefile, where a `curl -o` on line 1268 and a `$(shell
    uname)` on line 15 were read as one dropper. A composite is a claim
    that a file does one thing; a distance makes it a claim that one part
    of the file does it."""

    all_of: tuple[Any, ...] = ()
    any_of: tuple[Any, ...] = ()
    unless: tuple[Any, ...] = ()
    threshold: float = 0.0
    window: int = 0
    ast_query: Any = None
    """The compiled query for a `kind: ast` match. See `detect/astquery.py`.

    Typed loosely to keep this module free of a detector import at module
    scope: the loader knows how to build one, and the detector knows how to
    run it."""
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    prefilter: tuple[bytes, ...] = ()
    """Literals for which at least one must be present for this rule to match.

    Computed once at load time (see :func:`_extract_prefilter`). Empty means no
    prefilter is possible and the rule is evaluated against every candidate
    file."""
    prefilter_folded: tuple[bytes, ...] = ()
    """Lower-cased literals from `PatternCompiler.required_literals`, used only when `prefilter`
    is empty: one must appear in the file lower-cased. See `admits`."""

    branches: tuple[tuple[LiteralGate | None, LiteralGate | None], ...] = field(
        default=(), compare=False
    )
    """Per pattern, in order: two gates over the lower-cased file, each on lower-cased literals at
    least one of which every match of that pattern contains -- the required literals, then a
    sharper set tested only once the first passes. None is no condition; a pattern with neither
    always runs. See `regex_for`."""
    sources: tuple[str, ...] = field(default=(), compare=False, repr=False)
    """The patterns themselves, to compile the subset a file needs."""
    rule_id: str = field(default="", compare=False, repr=False)
    folds: bool = field(default=False, compare=False)
    """Whether any branch has a gate, which reads the lower-cased file."""
    subsets: dict[tuple[int, ...], re.Pattern[bytes]] = field(
        default_factory=dict, compare=False, repr=False
    )
    """Compiled alternations of the patterns a file can match, keyed by their positions."""
    plans: dict[re.Pattern[bytes], Plan | None] = field(
        default_factory=dict, compare=False, repr=False
    )
    """Where each of this rule's regexes can start a match (`rules/anchored`), worked out once."""

    SUBSETS_KEPT: ClassVar[int] = 256

    BUDGET_FLOOR: ClassVar[float] = 2.0
    """CPU seconds one rule may spend on one file, at least (S7). A linear rule takes 0.2 to 0.4 s
    on 10 MB (`rules/anchored`); test_rule_time.py holds every bundled rule under a quarter of the
    budget on hostile input. A constant, never configuration: a scanned tree must not raise it."""
    BUDGET_PER_MB: ClassVar[float] = 1.0
    """CPU seconds more per MiB of the file."""

    def budget(self, size: int) -> float:
        return max(self.BUDGET_FLOOR, self.BUDGET_PER_MB * size / (1 << 20))

    def matches(
        self, regex: re.Pattern[bytes], data: bytes, folded: bytes | None = None
    ) -> Iterator[re.Match[bytes]]:
        """`regex.finditer(data)`, exactly, trying `regex` only where a match can start.
        `regex` is this rule's (`regex_for`); `folded` is `data.lower()` when the caller has it.
        Raises RuleOverBudget once the search has spent more CPU than `budget` (S7)."""
        if regex not in self.plans:
            self.plans[regex] = AnchoredSearch.plan(regex)
        return self._budgeted(
            AnchoredSearch.matches(regex, self.plans[regex], data, folded), len(data)
        )

    def _budgeted(self, found: Iterator[re.Match[bytes]], size: int) -> Iterator[re.Match[bytes]]:
        """`found`, with the CPU spent inside the search (not the caller's, between matches)
        summed and checked after each match and at the end. One search that never returns is not
        stopped here (`re` cannot be interrupted): the worker's RLIMIT_CPU ends that unit as
        OPERATIONAL.FILE.WORKER_HUNG (engine/isolation/supervisor.py)."""
        budget, spent = self.budget(size), 0.0
        while True:
            started = time.thread_time()
            match = next(found, None)
            spent += time.thread_time() - started
            if spent > budget:
                raise RuleOverBudget(self.rule_id, spent, budget)
            if match is None:
                return
            yield match

    def search(
        self, regex: re.Pattern[bytes], data: bytes, folded: bytes | None = None
    ) -> re.Match[bytes] | None:
        """`regex.search(data)`, exactly: the first of `matches`. Every run of a rule's regex goes
        through here or `matches`, so the matcher's bounds hold for the whole rule set (the
        architecture test `test_rule_regexes_run_only_through_the_matcher`)."""
        return next(self.matches(regex, data, folded), None)

    def regex_for(self, data: bytes, folded: bytes | None = None) -> re.Pattern[bytes] | None:
        """The regex that finds exactly this rule's matches in `data`, cheapest first; None when
        nothing can match.

        Only the patterns that can match somewhere in `data` run. A pattern whose every match
        contains one of its literals cannot match a file holding none of them, and an alternation
        tries its branches in order at each position: a branch that cannot match anywhere changes
        neither which branch matches there nor where scanning resumes. So the alternation of the
        remaining patterns, in their order, finds the same matches in the same order -- and the
        engine stops trying seventeen branches at every byte of a file where one of them had a
        literal present. Callers read only a match's span and text, never its group numbers.
        """
        if not self.branches:
            return self.regex if self.admits(data, folded) else None
        # Without gates nothing reads it, so the file is not lowered for nothing.
        lowered = folded if folded is not None else (data.lower() if self.folds else data)
        chosen: list[int] = []
        for position, (required, sharper) in enumerate(self.branches):
            if required is not None and not required.present(lowered):
                continue
            if sharper is not None and not sharper.present(lowered):
                continue
            chosen.append(position)
        if not chosen:
            return None
        if len(chosen) == len(self.branches):
            return self.regex
        key = tuple(chosen)
        found: re.Pattern[bytes] | None = self.subsets.get(key)
        if found is None:
            found = self._subset(key)
            if found is not None and len(self.subsets) < self.SUBSETS_KEPT:
                self.subsets[key] = found
        return found

    def _subset(self, positions: tuple[int, ...]) -> re.Pattern[bytes] | None:
        """The alternation of the patterns at `positions`, compiled as the whole rule was; the
        whole rule's regex if that cannot be done identically."""
        try:
            subset = PatternCompiler.validate_pattern(
                "|".join(f"(?:{self.sources[i]})" for i in positions), rule_id=self.rule_id
            )
        except (re.error, RulePackError, UnsafePatternError):
            return self.regex
        if self.regex is None or subset.flags != self.regex.flags:
            return self.regex
        return subset

    def admits(self, data: bytes, folded: bytes | None = None) -> bool:
        """Whether this rule could match `data` at all; False means its regex need not run.

        `folded` is `data.lower()`, passed by a caller that tests many rules against one file so
        it is computed once; computed here otherwise.
        """
        if self.prefilter:
            return any(literal in data for literal in self.prefilter)
        if self.prefilter_folded:
            lowered = data.lower() if folded is None else folded
            return any(literal in lowered for literal in self.prefilter_folded)
        return True


@dataclass(frozen=True, slots=True)
class CompiledRule:
    """A rule plus its resolved matching strategy."""

    rule: Rule
    match: CompiledMatch

    @property
    def id(self) -> str:
        return self.rule.id


@dataclass(frozen=True, slots=True)
class RulePack:
    """A named, versioned collection of rules."""

    id: str
    version: str
    license: str
    rules: tuple[CompiledRule, ...]
    source: str = ""
    description: str = ""
    content_hash: str = ""

    def __len__(self) -> int:
        return len(self.rules)

    def __iter__(self) -> Iterator[CompiledRule]:
        return iter(self.rules)


__all__ = ["CompiledMatch", "CompiledRule", "RuleOverBudget", "RulePack"]
