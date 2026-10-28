"""Running the detectors: every enabled file detector over each unit, under the file's time budget
and through the cache, in a worker pool where the source and the size allow it; the repository and
graph detectors once each; a detector's findings dropped where the configuration disables its
rules; and each dependency annotated with what the checks concluded.

A file whose checks did not all run is reported, never cached, and leaves the scan incomplete.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import TYPE_CHECKING

from cordon_scanner.detect.agents.agent_judge import JudgeGate
from cordon_scanner.detect.base import (
    FileUnit,
    ScanContext,
    Unit,
)
from cordon_scanner.engine.cache import CacheKey
from cordon_scanner.engine.parallel import ParallelScanner, WorkItem
from cordon_scanner.engine.pipeline.accumulator import Accumulator
from cordon_scanner.engine.pipeline.archives import ArchiveMembers
from cordon_scanner.engine.pipeline.constants import (
    ADVISORY_DETECTORS,
    ALWAYS_RUN,
)
from cordon_scanner.engine.pipeline.operational import OperationalFinding
from cordon_scanner.engine.window_pass import WindowPass
from cordon_scanner.foundation.models import Category, Finding, Severity
from cordon_scanner.foundation.results import Dependency

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from cordon_scanner.detect.base import Detector
    from cordon_scanner.engine.engine import Engine


class Detection:
    """Runs the detectors over the scan's units."""

    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self.cache = engine.cache
        self.config = engine.config
        self.detectors = engine.detectors
        self.progress = engine.progress
        self.rules = engine.rules

    def inspect_file(
        self,
        unit: FileUnit,
        ctx: ScanContext,
        acc: Accumulator,
        detectors: list[Detector],
        signature: str,
    ) -> list[Finding]:
        """Run every file detector over one unit, via the cache.

        The cache is keyed on content plus everything that could change a
        finding, so a hit is provably identical to a cold run. A test asserts
        that equivalence rather than assuming it, because a stale cached "clean"
        is a false negative and false negatives are the failure that matters.
        """
        key = self.cache_key(unit, ctx, signature)

        cached = self.cache.get(key)
        if cached is not None:
            return list(cached)

        produced: list[Finding] = []
        budget = self.config.limits.per_file_timeout
        # `perf_counter`, not `monotonic`. Windows' monotonic clock ticks about
        # every 15 milliseconds, so a per-file budget smaller than one tick
        # measured zero elapsed time and never tripped -- the same coarse-clock
        # failure that made `--timeout 0` a no-op there. perf_counter is the
        # high-resolution timer and is what a sub-second budget needs.
        started = time.perf_counter()
        skipped: list[str] = []
        skipped_judge = False

        skipped_judge = self.each_detector(
            detectors, budget, started, skipped, produced, unit, ctx, acc
        )

        # The rest of an oversized file, a window at a time (`core/windows.py`). The workers make
        # the same call (`ParallelScanner._inspect_batch`), so a parallel scan reads as far.
        windowed, intact = WindowPass.run(
            unit,
            [
                d
                for d in detectors
                if d.id not in skipped and not (d.id == JudgeGate.ID and skipped_judge)
            ],
            lambda detector, part: self.run(detector, part, ctx, acc),
            produced,
        )
        produced.extend(windowed)
        if not intact:
            acc.complete = False
            produced.append(ArchiveMembers.changed_while_read(unit.path))

        if skipped:
            Detection.over_budget(acc, produced, unit, budget, skipped)
            # Not cached below, because acc.complete is now False.
            return produced

        # Every finding carries the hash of the file it came from, recorded once here
        # rather than in each of eleven detectors. `_collapse_repeats` is the only
        # reader: it is what lets "the same credential in 179 directories" be told from
        # "179 files that happen to start with the same RSA header".
        produced = [
            f.with_file_hash(unit.content.sha256) if f.location.path == unit.path else f
            for f in produced
        ]

        # Only a complete result is cached. Caching the output of a run that hit
        # a limit would make the degradation permanent and invisible.
        if acc.complete:
            self.cache.put(key, produced)

        return produced

    def each_detector(
        self,
        detectors: list[Detector],
        budget: float,
        started: float,
        skipped: list[str],
        produced: list[Finding],
        unit: FileUnit,
        ctx: ScanContext,
        acc: Accumulator,
    ) -> bool:
        """Every detector over the unit, each under the file's time budget, the judge last."""
        for detector in JudgeGate.last(detectors):
            # Checked between detectors rather than inside one. Python's `re`
            # cannot be interrupted mid-match -- a single call holds the
            # interpreter until it returns -- so nothing in this process can
            # bound one pathological regex. What this does bound is
            # accumulation: fifty detectors and several hundred rules over a
            # very large file. The single-regex case is prevented at load time
            # instead, by PatternCompiler rejecting the shapes that backtrack.
            #
            # Stating the division plainly because the previous docstring did
            # not: it named this timeout as the backstop for catastrophic
            # regexes, the timeout was never implemented, and had it been it
            # could not have stopped the case it was named for.
            #
            # The budget never cuts the detectors that find malware and secrets. It did, and that
            # was a way to hide a payload: pad a file with near-miss credentials so an earlier
            # detector spends the budget, and `capability` never ran on it -- an INFO note and a
            # passing scan. Those detectors' patterns are validated linear at load and the file is
            # capped in size, so their cost is bounded without the budget; the total timeout still
            # ends the scan. What the budget cuts now is everything else, and it says which.
            if (
                budget > 0
                and time.perf_counter() - started >= budget
                and detector.id not in ALWAYS_RUN
            ):
                skipped.append(detector.id)
                continue

            # The judge reads the grey band only, after every other detector (review 98, AG-5).
            if detector.id == JudgeGate.ID and not JudgeGate.wants(produced):
                skipped_judge = True
                continue
            produced.extend(self.run(detector, unit, ctx, acc))
        return skipped_judge

    @staticmethod
    def over_budget(
        acc: Accumulator, produced: list[Finding], unit: FileUnit, budget: float, skipped: list[str]
    ) -> None:
        """Detectors skipped on this file because its time budget ran out: the scan is incomplete, and says so."""
        acc.complete = False
        produced.append(
            OperationalFinding.build(
                path=unit.path,
                rule_id="OPERATIONAL.FILE.TIMEOUT",
                message=(
                    f"This file exceeded its {budget:.0f}s budget, so these detectors did not "
                    f"run on it: {', '.join(skipped)}. The malware, obfuscation, secret and "
                    f"binary detectors ran in full."
                ),
                remediation=(
                    "Raise limits.per_file_timeout, or exclude the file if it "
                    "is generated output rather than source."
                ),
            )
        )

    def parallel(
        self,
        units: list[FileUnit],
        root: Path,
        ctx: ScanContext,
        acc: Accumulator,
        detectors: list[Detector],
        signature: str,
        *,
        carry_content: bool = False,
    ) -> list[Finding]:
        """Inspect files across a worker pool.

        The cache is consulted in this process first, so only genuine misses are
        distributed. A warm scan therefore does almost no cross-process work,
        which is the case a commit-time hook actually hits.

        A pool that cannot start falls back to serial execution. On a platform
        where processes cannot be spawned, a slower scan is the correct outcome;
        a failed one is not.
        """
        by_path = {unit.path: unit for unit in units}
        pending: list[WorkItem] = []
        results: list[Finding] = []

        self.work_items(units, ctx, signature, results, pending, carry_content)

        if not pending:
            return results

        def report(indices: Sequence[int]) -> None:
            # Called as each batch's results arrive, so the count moves while
            # the pool is still working. Advancing after `run` returned meant a
            # parallel scan sat at 0 for its whole duration and then jumped to
            # complete, which reads exactly like the hang it exists to rule out.
            for index in indices:
                self.progress.advance(units[index].path)

        produced = ParallelScanner.run(
            config=self.config,
            root=str(root),
            files=pending,
            workers=ParallelScanner.worker_count(
                self.config.limits.max_workers, len(pending), sum(item[2] for item in pending)
            ),
            # The set the parent already filtered. Without it the worker ran
            # every detector it could find, and a scan's findings depended on
            # the machine's core count.
            detector_ids=[getattr(d, "id", "") for d in detectors],
            # The parent already walked the tree. Sending the result costs one
            # pickle; recomputing it costs a full traversal per worker.
            inventory=ctx.repository,
            # And the parts of the context the inventory cannot produce: which
            # FILES an install hook runs, and the import closure around them. A
            # worker rebuilding the context from the inventory alone knows that
            # `package.json` declares a `postinstall` and not that it runs
            # `scripts/setup.js`, so every composite gated on
            # `ctx.in_install_hook` was silently off in parallel.
            install_hook_paths=ctx.install_hook_paths,
            ci_hook_paths=ctx.ci_hook_paths,
            # And which bodies inside that closure the hooks never reach, for
            # the same reason: a worker cannot derive it, and one that had the
            # paths without it would apply install-time context more widely than
            # the parent does.
            install_deferred_lines=ctx.install_deferred_lines,
            # An image's members are judged as an image's: a binary there is what it ships.
            image=ctx.image,
            install_entry_paths=ctx.install_entry_paths,
            consumer_install_paths=ctx.consumer_install_paths,
            package_facts={
                "package_distribution": ctx.package_distribution,
                "distribution": ctx.distribution,
                "tree_paths": ctx.tree_paths,
                "import_entry_paths": ctx.import_entry_paths,
                "package_repository": ctx.package_repository,
            },
            on_batch=report,
        )

        if produced is None:
            self.inspect_here(pending, by_path, results, ctx, acc, detectors, signature)
            return results

        self.merge_worker_results(produced, units, results, acc, ctx, signature)

        return results

    def inspect_here(
        self,
        pending: list[tuple[int, str, int, str, bytes | str | None]],
        by_path: dict[str, FileUnit],
        results: list[Finding],
        ctx: ScanContext,
        acc: Accumulator,
        detectors: list[Detector],
        signature: str,
    ) -> None:
        """Every pending file inspected in this process: the pool did not run."""
        # The pool did not run. Fall back rather than lose coverage. `None`
        # rather than an empty list, so a pool that ran and legitimately
        # found nothing is not re-scanned from scratch.
        for _index, path, _size, _digest, _carried in pending:
            unit = by_path[path]
            results.extend(self.inspect_file(unit, ctx, acc, detectors, signature))
            self.progress.advance(unit.path)

    def work_items(
        self,
        units: list[FileUnit],
        ctx: ScanContext,
        signature: str,
        results: list[Finding],
        pending: list[tuple[int, str, int, str, bytes | str | None]],
        carry_content: bool,
    ) -> None:
        """The units a worker can take, each with the bytes it must carry when the source cannot be re-read."""
        for index, unit in enumerate(units):
            key = self.cache_key(unit, ctx, signature)
            cached = self.cache.get(key)
            if cached is not None:
                results.extend(cached)
                # A cache hit is a file accounted for. Counting only the misses
                # made a warm scan appear to stall at zero and then finish.
                self.progress.advance(unit.path)
            else:
                # The parent's content hash travels with the work item, so the
                # worker can tell whether it read the same bytes -- and, for a
                # source the worker must not re-read, the bytes themselves.
                pending.append(
                    (
                        index,
                        unit.path,
                        len(unit.content.raw),
                        unit.content.sha256,
                        # An archive member has no path on disk to re-read. The whole of an
                        # oversized one travels, so the worker can sweep it as well. Nor does
                        # a hook's inline program (`core.inline_programs`).
                        unit.content.carried
                        if carry_content or "!" in unit.path or "#" in unit.path
                        else None,
                    )
                )

    def merge_worker_results(
        self,
        produced: list[tuple[int, list[Finding], bool]],
        units: list[FileUnit],
        results: list[Finding],
        acc: Accumulator,
        ctx: ScanContext,
        signature: str,
    ) -> None:
        """What the workers found, merged in the order of the units, and cached where trusted."""
        for index, findings, trusted in produced:
            unit = units[index]
            results.extend(findings)
            if not trusted:
                # The worker could not read the file, or read different bytes
                # than the parent hashed. Reported exactly as the serial path
                # reports an unreadable file, and never cached: storing it would
                # file a result under a key describing content the result was
                # not produced from.
                acc.complete = False
                results.append(
                    OperationalFinding.build(
                        path=unit.path,
                        rule_id="OPERATIONAL.FILE.UNREADABLE",
                        message=(
                            "A worker could not read this file, or read different "
                            "content than the scan had already hashed, so its checks "
                            "did not run on the content being reported."
                        ),
                        remediation=(
                            "Re-run the scan on a tree nothing else is writing to, or pass -j 1."
                        ),
                    )
                )
                continue
            if acc.complete:
                self.cache.put(self.cache_key(unit, ctx, signature), findings)

    def cache_key(self, unit: FileUnit, ctx: ScanContext, signature: str) -> CacheKey:
        return CacheKey(
            content_hash=unit.content.sha256,
            rulepack_hash=self.rules.content_hash,
            config_hash=self.config.fingerprint(),
            detector_signature=signature,
            path=unit.path,
            in_install_hook=ctx.in_install_hook(unit.path),
            language=unit.language or "",
        )

    def annotated(
        self,
        dependencies: tuple[Dependency, ...],
        findings: Iterable[Finding],
        ctx: ScanContext,
        units: list[FileUnit],
    ) -> tuple[Dependency, ...]:
        """Each dependency's shared record: its check statuses, path and locations."""
        if not dependencies:
            return dependencies
        from cordon_scanner.engine.inventory import DependencyRecords, InventoryContext

        findings = tuple(findings)
        advisory = next((d for d in self.detectors if d.id == "advisory"), None)
        database = (
            getattr(advisory, "_database", None)
            if advisory is not None and self.enabled(advisory, ctx)
            else None
        )
        failed = any(
            f.rule_id == "OPERATIONAL.DETECTOR.FAILED" and "'advisory'" in f.message
            for f in findings
        )
        wanted = {d.declared_in for d in dependencies} | {d.manifest_path for d in dependencies}
        texts = {u.path: u.content.text for u in units if u.path in wanted}
        return DependencyRecords.annotate(
            dependencies,
            findings,
            InventoryContext(
                advisory_database=database,
                advisory_failed=failed,
                offline=ctx.offline,
                checks=ctx.checks,
                texts=texts,
            ),
        )

    def enabled(self, detector: Detector, ctx: ScanContext) -> bool:
        if not self.config.detector_enabled(detector.id):
            return False
        if detector.requires.network and ctx.offline:
            return False
        return detector.applicable(ctx)

    def drop_disabled(self, produced: list[Finding]) -> list[Finding]:
        """Remove findings whose rule the configuration turned off.

        Applied to every detector's output rather than inside each detector, so
        a rule declared in Python is as disableable as one declared in YAML.
        Operational findings are never dropped: they describe the scan, and a
        configuration that could silence them could hide the fact that it had
        silenced everything else.
        """
        disabled = self.config.disabled_rules
        if not disabled:
            return produced
        return [
            f
            for f in produced
            if f.category is Category.OPERATIONAL or f.always_report or f.rule_id not in disabled
        ]

    def run(
        self, detector: Detector, unit: Unit, ctx: ScanContext, acc: Accumulator
    ) -> list[Finding]:
        """Run one detector over one unit, containing its failures.

        A detector that raises must not abort the scan, because one broken
        detector silently reducing coverage across every file is far worse than
        one loud finding saying it broke. The scan continues and reports itself
        as incomplete.
        """
        try:
            produced = list(detector.inspect(unit, ctx))
        except Exception as exc:  # noqa: BLE001
            acc.complete = False
            return [
                OperationalFinding.build(
                    path=getattr(unit, "path", "<graph>"),
                    rule_id="OPERATIONAL.DETECTOR.FAILED",
                    message=(
                        f"Detector {detector.id!r} failed on this file, so its checks "
                        f"did not run: {type(exc).__name__}: {exc}"
                    ),
                    remediation="Report this with the file that triggered it.",
                    severity=Severity.MEDIUM,
                )
            ]

        # The engine asserts that a file detector reports only about the file it
        # was given. A detector that reports about somewhere else is a bug, and
        # accepting it silently would make findings untraceable to their source.
        #
        # Graph and repository units have no single path, so the check applies
        # only where it is meaningful. Asserting `unit.path` unconditionally is
        # what made every graph detector crash the scan.
        if isinstance(unit, FileUnit):
            kept: list[Finding] = []
            stray: list[Finding] = []
            for finding in produced:
                if (
                    finding.category is not Category.OPERATIONAL
                    and finding.location.path != unit.path
                ):
                    stray.append(finding)
                else:
                    kept.append(finding)

            if stray:
                # Reported and dropped, not raised. This check sat outside the
                # `try` above, so `DetectorError` propagated out of `scan()` and
                # terminated the run -- meaning a detector that mislabelled one
                # finding killed the entire scan on the first file it touched,
                # inside the very method whose docstring says a broken detector
                # must not abort anything.
                acc.complete = False
                kept.append(
                    OperationalFinding.build(
                        path=unit.path,
                        rule_id="OPERATIONAL.DETECTOR.STRAY_FINDING",
                        message=(
                            f"Detector {detector.id!r} reported {len(stray)} finding(s) "
                            f"about other paths while inspecting this file "
                            f"({stray[0].location.path!r}). They were discarded."
                        ),
                        remediation=(
                            "Report this. A file detector must report only about the "
                            "file it was given, or findings cannot be traced to their "
                            "source."
                        ),
                        severity=Severity.MEDIUM,
                    )
                )
            produced = kept

        # A detector that hit a ceiling of its own knows something the engine
        # cannot observe from outside: that it answered fewer questions than it
        # was asked. Reading it here keeps `complete` meaning the same thing
        # whether the coverage was lost in the walk or inside a detector.
        degrading = [f for f in produced if f.degrades_coverage]
        if any(f.detector in ADVISORY_DETECTORS for f in degrading):
            acc.advisory_complete = False
        if any(f.detector not in ADVISORY_DETECTORS for f in degrading):
            acc.complete = False

        return self.drop_disabled(produced)


__all__ = ["Detection"]
