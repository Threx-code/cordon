"""One large file matched by several processes at once, each against a share of the rules.

YARA matches a file on one thread. A large binary against a large rule set (YARA-Forge's 12,455
rules) is where Cordon's time goes, and its matcher is mostly Python, so threads would share one
interpreter lock. Processes do not: each worker loads the kept pack once (`pack_cache`), and a file
from `LARGE` up is matched by every worker at the same time, each deciding its share
(`rule_shares`). The answers put together are the serial answer, rule for rule and string for
string, in the rule set's order:

- a share holds every rule its rules read, and every share holds the global rules;
- the file's bounds are the file's, not each share's: each worker reports what it spent of the
  places to try (`Places.MOST`) and of the matches held (`Hits.MOST`), and the file is refused
  when the totals pass either, as the serial match would have refused it;
- a worker's refusal refuses the file, with its reason;
- a rule in several shares (the globals) is reported once.

Used only from the scan's main process (a scan's own worker pool already spreads files across the
cores), for rule sets with at least `MIN_RULES` rules, with at most `MOST_WORKERS` workers, since
each holds the whole pack in memory. Workers are started with `spawn`, safe beside threads and the
same on every platform, and stopped when the engine is.
"""

from __future__ import annotations

import multiprocessing
from array import array
from collections.abc import Callable
from concurrent.futures import ProcessPoolExecutor
from typing import Any, ClassVar

from cordon_scanner.detect.binary.rule_engine.anchoring.places import Places
from cordon_scanner.detect.binary.rule_engine.hits import Hits, Match
from cordon_scanner.detect.binary.rule_engine.lang import RuleError, Rules
from cordon_scanner.detect.binary.rule_shares import RuleShares


class Worker:
    """What one worker process holds: the rules and their given module data, loaded once."""

    #: Deliberate process state: each worker process loads one engine, once, and holds it for its
    #: life; nothing a scan holds is kept here.
    engine: ClassVar[Any] = None
    why: ClassVar[Callable[[BaseException], str]] = str

    @staticmethod
    def load(
        engine_type: Callable[..., Any],
        why: Callable[[BaseException], str],
        rules_path: str,
        module_data: tuple[tuple[str, str], ...],
        use_cache: bool,
    ) -> None:
        """Called once in each worker, with the engine type and the refusal's wording passed in
        (by name), so this module imports neither."""
        Worker.engine = engine_type(rules_path, module_data, use_cache=use_cache, workers=1)
        Worker.why = why

    @staticmethod
    def match(data: bytes, timeout: float, share: frozenset[int]) -> tuple[Any, ...]:
        """("ok", matches, spent) or ("refused", why): a match as (rule, [(name, starts,
        lengths)]), the arrays as bytes, so the file's bytes are never sent back."""
        engine = Worker.engine
        spent: dict[str, int] = {}
        try:
            found = engine.rules.match(
                data, timeout=timeout, given=engine.given, subset=share, spent=spent
            )
        except RuleError as exc:
            return ("refused", Worker.why(exc))
        out = []
        for m in found:
            strings = []
            for name, hits in m.hits:
                kept = hits if isinstance(hits, Hits) else Hits(hits)
                strings.append((name, kept.starts.tobytes(), kept.lengths.tobytes()))
            out.append((m.rule, strings))
        return ("ok", out, spent)


class RulePool:
    """The workers for one rule-file engine, and the shares they decide."""

    #: Files from here up are matched in parallel; smaller ones cost less than handing them over.
    LARGE: ClassVar[int] = 1 << 20
    MIN_RULES: ClassVar[int] = 200
    MOST_WORKERS: ClassVar[int] = 4

    def __init__(
        self,
        rules: Rules,
        start: tuple[Any, ...],
        workers: int,
    ) -> None:
        """`start` is what each worker loads with (`Worker.load`'s arguments)."""
        self.rules = rules
        self.shares = RuleShares.of(rules.rules, min(workers, RulePool.MOST_WORKERS))
        self.order = {rule.name: i for i, rule in enumerate(rules.rules)}
        self._start = start
        self._executor: ProcessPoolExecutor | None = None

    @staticmethod
    def wanted(rules: Rules, workers: int) -> bool:
        """Whether a pool pays: several workers, a large rule set, and this the main process."""
        return (
            workers > 1
            and len(rules.rules) >= RulePool.MIN_RULES
            and multiprocessing.parent_process() is None
        )

    def executor(self) -> ProcessPoolExecutor:
        if self._executor is None:
            self._executor = ProcessPoolExecutor(
                max_workers=len(self.shares),
                mp_context=multiprocessing.get_context("spawn"),
                initializer=Worker.load,
                initargs=self._start,
            )
        return self._executor

    def match(self, data: bytes, timeout: float) -> list[Match]:
        """`data` matched by every share at once: the serial answer, or the serial refusal."""
        results = [
            f.result()
            for f in [self.executor().submit(Worker.match, data, timeout, s) for s in self.shares]
        ]
        refused = [r[1] for r in results if r[0] == "refused"]
        if refused:
            raise RuleError(refused[0])
        places = sum(r[2].get("places", 0) for r in results)
        held = sum(r[2].get("matches", 0) for r in results)
        if places > Places.MOST:
            from cordon_scanner.detect.binary.rule_engine.pattern import Unbounded

            raise RuleError("the file has too many places to try") from Unbounded(
                f"more than {Places.MOST:,} places to try in one file, the shares together"
            )
        if held > Hits.MOST:
            from cordon_scanner.detect.binary.rule_engine.pattern import TooManyMatches

            raise RuleError("the file has too many matches") from TooManyMatches(
                f"more than {Hits.MOST:,} matches in one file, the shares together"
            )
        found: list[tuple[int, Match]] = []
        reported: set[str] = set()  # a global rule is in every share, and is reported once
        for _, matches, _ in results:
            for rule_name, strings in matches:
                if rule_name in reported:
                    continue
                reported.add(rule_name)
                rule = self.rules.rules[self.order[rule_name]]
                hits: list[tuple[str, Hits]] = []
                for name, starts, lengths in strings:
                    kept = Hits()
                    kept.starts, kept.lengths = array("q", starts), array("q", lengths)
                    hits.append((name, kept))
                made = Match(rule.name, list(rule.tags), dict(rule.meta), data=data, hits=hits)  # type: ignore[arg-type]
                found.append((self.order[rule_name], made))
        return [m for _, m in sorted(found, key=lambda pair: pair[0])]

    def close(self) -> None:
        if self._executor is not None:
            self._executor.shutdown(wait=False, cancel_futures=True)
            self._executor = None


__all__ = ["RulePool", "Worker"]
