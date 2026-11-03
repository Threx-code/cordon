"""Facts about the scanned tree that the detectors are handed with each file: which files are a
package's entry points, which a skill runs, which native code ships, where its provenance is
declared, and which files were already labelled once (`TreeFacts`).

## The scanner's facts for the rule file (`ScanFactsGathering`)

A rule file importing `package`, `js` or `python` (`detect/binary/modules/scanner_facts`) reads
what the package verdict reads, which exists only once every detector has run. So its files are
not matched during detection (`RuleFileDetector.defers`); `Stages.detect` gathers the facts here,
then runs the rule-file detector again over the files, on the same worker pool, with the facts on
the context. Its findings then take every later step a finding takes -- the ceilings, the
suppressions, the folds, the verdict -- and the verdict reuses the facts gathered here rather
than computing them twice.

    detection ──► gather (profile + flows + registry + campaigns) ──► deferred rule pass
                                    │                                        │
                                    └──── the verdict's facts ◄── findings ──┘

    `verdict`     the dict the verdict reads: the capability profile and reached flows
                  (`Engine._capability_profile`) and the registry facts (`History`)
    `scan_facts`  what the modules read (`ScanFacts`): those, reshaped, and the campaign siblings
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.detect.base import (
    FileUnit,
    ScanContext,
)
from cordon_scanner.engine.pipeline.history import History
from cordon_scanner.foundation.errors import SourceError

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

    from cordon_scanner.detect.base import CapabilityLabelling, CapabilityMark
    from cordon_scanner.engine.engine import Engine
    from cordon_scanner.engine.pipeline.accumulator import Accumulator


class TreeFacts:
    """Facts about the scanned tree, gathered once for every detector."""

    @staticmethod
    def provenance(root: Path) -> tuple[bool, str | None, str | None, bool]:
        """The commit and remote this scan describes.

        `Repository` declared both fields, `to_dict` serialised both, and
        nothing ever set either -- so every report and every SARIF upload
        recorded `null` for the two values that say *which* code was examined.
        A result nobody can tie to a commit is a result nobody can act on later:
        it says a repository was clean without saying which version of it.

        `GitRepository.discover` already computed both, including stripping any
        credential from the remote, and its answer was simply never asked for.

        `is_git` had the identical defect and is returned here for the same
        reason. It gated whether any repository-scoped detector runs at all, so
        leaving it false meant the history checks were shipped and never
        executed -- a detector that cannot run is indistinguishable from one
        that found nothing.

        Failure is silent on purpose. A directory that is not a repository is
        the ordinary case, not a degraded scan, and it is already visible in the
        report as an absent revision.
        """
        from cordon_scanner.sources.registry import GitRepository

        try:
            info = GitRepository.discover(root)
        except (SourceError, OSError):  # pragma: no cover - defensive
            return (False, None, None, False)
        if info is None:
            return (False, None, None, False)
        # Whether the target is the repository root, which is a different question
        # from whether a repository is above it. Resolved on both sides, so a
        # symlinked or relative target does not read as a subdirectory of itself.
        try:
            at_root = Path(info.root).resolve() == Path(root).resolve()
        except OSError:  # pragma: no cover - defensive
            at_root = False
        return (True, info.revision, info.remote, at_root)

    @staticmethod
    def shipped_native(units: Iterable[FileUnit]) -> frozenset[str]:
        """Paths whose bytes begin with ELF, PE or Mach-O magic: a binary the package ships (census A)."""
        from cordon_scanner.detect.registry import NATIVE_FORMATS, BinaryDetector

        ids = ((u.path, BinaryDetector.identify(u.content.raw)) for u in units if u.content)
        return frozenset(p for p, f in ids if f is not None and f.name in NATIVE_FORMATS)

    @staticmethod
    def entry_points_reached(
        deferred: frozenset[tuple[str, int, int]], agent_run: set[str]
    ) -> frozenset[tuple[str, int, int]]:
        """Deferred bodies, less those in code an agent runs: a skill script's functions and an MCP
        server's handlers are called by the agent by name, so none of them is unreached. Counted as
        deferred, a skill script appending to `/etc/passwd` and `/etc/crontab` from its functions
        had no install-time finding at all (review 98)."""
        return frozenset(t for t in deferred if t[0] not in agent_run)

    @staticmethod
    def skill_scripts(units: Sequence[FileUnit]) -> set[str]:
        """Scripts an agent skill ships (`LoadPath.skill_script`)."""
        from types import SimpleNamespace

        from cordon_scanner.detect.registry import LoadPath

        tree = SimpleNamespace(tree_paths=frozenset(u.path for u in units))
        return {
            u.path
            for u in units
            if LoadPath.skill_script(u.path, tree)  # type: ignore[arg-type]
        }

    @staticmethod
    def labelled_once(
        detector: CapabilityLabelling,
        unit: FileUnit,
        ctx: ScanContext,
        cache: dict[str, Any] | None,
    ) -> tuple[Sequence[CapabilityMark], Sequence[object]] | None:
        """`detector.labelled(unit, ctx)`, computed once per file for everything that asks."""
        if cache is None:
            return detector.labelled(unit, ctx)
        if unit.path not in cache:
            try:
                cache[unit.path] = detector.labelled(unit, ctx)
            except Exception as error:  # re-raised to each caller below  # noqa: BLE001
                cache[unit.path] = error
        held: tuple[Sequence[CapabilityMark], Sequence[object]] | Exception | None = cache[
            unit.path
        ]
        if isinstance(held, Exception):
            raise held
        return held


class CrossFileFlows:
    """Item 60's join: the workers' summaries (`js.*` facts) composed across the package's require
    graph (`CrossFile.compose`, facts only, never a file read here), then each calling file with a
    flow re-graded by the capability detector with its flows on the context, in supervised workers
    as detection runs. The capability detector's first-pass findings for those files are replaced,
    so a flow is reported once, graded at the caller (rule 5).

        detection ─► acc.facts[js.*] ─► compose ─► callers ─► capability detector again ─► replace
    """

    DETECTOR: ClassVar[str] = "capability"

    @staticmethod
    def regrade(
        engine: Engine,
        detectors: Sequence[Any],
        units: list[FileUnit],
        acc: Accumulator,
        root: Path,
        ctx: ScanContext,
        *,
        carry_content: bool,
        where: str,
    ) -> None:
        """Re-grade the calling files; the steps after keep the scan's own context."""
        from cordon_scanner.detect.registry import CrossFileJoin
        from cordon_scanner.engine.cache import CacheSignature

        capability = [d for d in detectors if getattr(d, "id", "") == CrossFileFlows.DETECTOR]
        if not capability:
            return
        flows = CrossFileJoin.cross_file(units, acc.facts)
        unresolved = CrossFileJoin.unresolved(acc.facts, acc.findings)
        # Where the join is incomplete, a finding lowered on the join's word is graded again
        # without it (note 78; rule 3: unknown is never "no caller passes a reply").
        lowered = CrossFileJoin.lowered(acc.findings) if unresolved else set()
        if not flows and not lowered:
            return
        callers = [u for u in units if u.path in flows or u.path in lowered]
        graded = replace(ctx, cross_file_flows=flows, cross_file_unresolved=unresolved)
        signature = CacheSignature.scan_signature(capability, graded, engine.config)
        again = engine.detection.parallel(
            callers, root, graded, acc, capability, signature, carry_content=carry_content,
            where=where,
        )  # fmt: skip
        if any(f.rule_id.startswith("OPERATIONAL.") for f in again):
            # A re-grade that did not finish keeps the first pass's findings beside its own gap:
            # nothing already found is lost to a worker that died the second time.
            acc.add(again)
            return
        paths = {u.path for u in callers}
        acc.findings[:] = [
            f
            for f in acc.findings
            if not (f.detector == CrossFileFlows.DETECTOR and f.location.path in paths)
        ]
        acc.add(again)


class ScanFactsGathering:
    """`gather`: the verdict's facts and the rule modules' facts, from one computation; and
    `deferred`, the rule file's pass over them."""

    #: The measurement runs' marker (`ReachedFlows.MEASURE`): a content-only run, where the
    #: gathered facts hold no registry record (`ScanFacts`).
    CONTENT_ONLY: ClassVar[str] = "CORDON_MEASURE_FEATURES"

    @staticmethod
    def content_only() -> bool:
        import os

        return os.environ.get(ScanFactsGathering.CONTENT_ONLY) == "1"

    @staticmethod
    def verdict(
        engine: Engine,
        units: Sequence[FileUnit],
        ctx: ScanContext,
        facts: dict[str, dict[str, list[Any]]],
    ) -> dict[str, float]:
        """The facts the package verdict reads (`Stages.fold_and_judge`)."""
        return {
            **engine._capability_profile(units, ctx, facts),
            **History.registry_facts(units),
        }

    @staticmethod
    def gather(
        engine: Engine,
        units: Sequence[FileUnit],
        ctx: ScanContext,
        facts: dict[str, dict[str, list[Any]]],
    ) -> tuple[dict[str, float], dict[str, Any]]:
        """(the verdict's facts, the modules' facts). `facts` is the workers' (`Accumulator.facts`)."""
        verdict = ScanFactsGathering.verdict(engine, units, ctx, facts)
        return verdict, {
            "identity": ScanFactsGathering.identity(units),
            "can": ScanFactsGathering.capabilities(verdict),
            "flows": ScanFactsGathering.flows(verdict),
            "registry": ScanFactsGathering.registry(
                verdict, content_only=ScanFactsGathering.content_only()
            ),
            "campaign": ScanFactsGathering.campaigns(units, ctx),
        }

    @staticmethod
    def deferred(
        engine: Engine,
        detectors: Sequence[Any],
        units: list[FileUnit],
        acc: Accumulator,
        root: Path,
        ctx: ScanContext,
        *,
        carry_content: bool,
        where: str,
    ) -> None:
        """The deferred pass: when a detector defers (`RuleFileDetector.defers`), gather the
        facts, keep the verdict's on `acc`, and run the deferring detectors over every file with
        the facts on the context -- across the worker pool where detection used one, since the
        context (facts included) is what a worker receives and what a file's cache key holds."""
        from cordon_scanner.engine.cache import CacheSignature

        later = [d for d in detectors if callable(getattr(d, "defers", None)) and d.defers(ctx)]
        if not later:
            return
        acc.verdict_facts, facts = ScanFactsGathering.gather(engine, units, ctx, acc.facts)
        ctx = replace(ctx, scan_facts=facts)
        signature = CacheSignature.scan_signature(later, ctx, engine.config)
        # In supervised workers, one as readily as many (item 28), as the first pass is.
        acc.add(
            engine.detection.parallel(
                units, root, ctx, acc, later, signature, carry_content=carry_content, where=where
            )
        )

    @staticmethod
    def verdict_facts(
        engine: Engine, units: Sequence[FileUnit], ctx: ScanContext, acc: Accumulator
    ) -> dict[str, float]:
        """The verdict's facts: those the deferred pass gathered, else computed now."""
        if acc.verdict_facts is not None:
            return acc.verdict_facts
        return ScanFactsGathering.verdict(engine, units, ctx, acc.facts)

    @staticmethod
    def identity(units: Sequence[FileUnit]) -> list[str] | None:
        """[ecosystem, name, version] of the release the scan is, as the registry facts read it."""
        files = [u for u in units if isinstance(u, FileUnit)]
        distribution = History.history_distribution(files)
        if not distribution:
            return None
        found = History.history_identity(files, distribution)
        return list(found) if found is not None else None

    @staticmethod
    def campaigns(units: Sequence[FileUnit], ctx: ScanContext) -> dict[str, list[int]]:
        """Per npm package (by its archive), [condemned siblings, most facets one shares], as the
        campaign detector computes them."""
        from cordon_scanner.detect.registry import CampaignSiblings

        out: dict[str, list[int]] = {}
        for unit in units:
            found = CampaignSiblings.siblings_of(unit, ctx)
            if found is None:
                continue
            facets, siblings = found
            shared = max((len(CampaignSiblings.shared(facets, s)) for s in siblings), default=0)
            out[unit.content.path.rpartition("!")[0]] = [len(siblings), shared]
        return out

    @staticmethod
    def flows(facts: Mapping[str, float]) -> list[list[str]]:
        """The flow facts as [place, source, sink, destination]: sinks and destinations are one
        word each, so a key splits from the right (sources may hold an underscore)."""
        out = []
        for key in facts:
            place, mark, rest = key.partition("_flow_")
            if mark and place and rest.count("_") >= 2:
                source, sink, destination = rest.rsplit("_", 2)
                out.append([place, source, sink, destination])
        return sorted(out)

    @staticmethod
    def capabilities(facts: Mapping[str, float]) -> list[list[str]]:
        """The profile's capability facts as [place, capability]."""
        out = []
        for key, value in facts.items():
            place, mark, name = key.partition("_can_")
            if mark and place and name and value:
                out.append([place, name])
        return sorted(out)

    @staticmethod
    def registry(facts: Mapping[str, float], *, content_only: bool) -> dict[str, float] | None:
        """The registry record's facts, or None: none was acquired, or the run is content-only
        (registry knowledge never enters a content-only number)."""
        reg = {k: v for k, v in facts.items() if k.startswith("reg_")}
        if content_only or not reg.get("reg_known"):
            return None
        return reg


__all__ = ["ScanFactsGathering", "TreeFacts"]
