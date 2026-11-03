"""What the parent's verdict and intent steps read of a file, read in the worker (item 56, phase (a),
sites 9 and 10): capability labels, download runs, the intent observer's per-effect timing, its
concealment and gate facts, and the reached-flow facts. They cross as declared facts
(`engine/isolation/facts.py`); the parent keeps every selection it makes today (which files, in what
order, how many) and reads these instead of running a detector over the file.

```
  worker, per unit (after its detectors)          parent
  ─────────────────────────────────────           ──────────────────────────────────────────────
  cap.label     capability names (labelled)       Engine._capability_profile: per place, in unit
  cap.error     the labelling raised              order, the same 1 MB and file-count limits
  cap.download  it runs a download                Engine._intent_observation: roles, ranking and
  intent.effect [capability, deferred]            limits as today; per file, these facts
  intent.fact   concealment and gate facts        ReachedFlows.of: per place, `{place}_{suffix}`
  reached.flow  a reached-flow fact's suffix
  js.*          a JavaScript file's cross-file      CrossFileFlows: joined across the package's
                summaries (item 60)                 require graph, the callers re-graded
```

A file is labelled in the worker when the parent could ask for it: in an install, import or agent
place and at most 1 MB (the profile), or one of the intent observer's own files (first-party code,
within its byte limit, not truncated or binary). A label that raises is `cap.error`: the profile skips
the file and the intent observer reports it unexamined, as when the parent's call raised.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    from cordon_scanner.detect.base import ScanContext

#: The profile's size test (`Engine._capability_profile`): a file over this is not labelled there.
PROFILE_BYTES = 1_000_000


class WorkerAnalysis:
    """The worker's side: the facts for one unit, into `WorkerFacts`."""

    @staticmethod
    def produce(unit: Any, ctx: ScanContext, detectors: tuple[Any, ...]) -> None:
        from cordon_scanner.decide.intent import IntentObserver
        from cordon_scanner.detect.base import CapabilityLabelling
        from cordon_scanner.engine.isolation.facts import WorkerFacts

        labeller = next((d for d in detectors if isinstance(d, CapabilityLabelling)), None)
        profiled = unit.content.size <= PROFILE_BYTES and unit.path in (
            ctx.install_hook_paths | ctx.install_entry_paths | ctx.import_entry_paths
            | ctx.agent_run_paths
        )  # fmt: skip
        observed = IntentObserver.applies(ctx) and IntentObserver.reads(unit)
        if labeller is not None and (profiled or observed):
            try:
                labelled = labeller.labelled(unit, ctx)
            except Exception:  # the parent's call raising: the same outcome  # noqa: BLE001
                WorkerFacts.add("cap.error", "raised")
                labelled = None
            else:
                for name in sorted({hit.capability.value for hit in (labelled or ((),))[0]}):
                    WorkerFacts.add("cap.label", name)
                WorkerAnalysis._download(unit)
                if observed:
                    for fact in IntentObserver.file_facts(unit, ctx, labelled):
                        kind, value = fact
                        WorkerFacts.add(kind, value)
        WorkerAnalysis._reached(unit, ctx)

    @staticmethod
    def _download(unit: Any) -> None:
        from cordon_scanner.detect.registry import DownloadFlow
        from cordon_scanner.engine.isolation.facts import WorkerFacts

        if DownloadFlow.runs_download(unit.content.text, unit.language):
            WorkerFacts.add("cap.download", "runs")

    @staticmethod
    def _reached(unit: Any, ctx: ScanContext) -> None:
        from cordon_scanner.detect.registry import ReachedFlows
        from cordon_scanner.engine.isolation.facts import WorkerFacts

        if not ReachedFlows.reads(unit, ctx):
            return
        python = unit.path.lower().endswith(".py")
        for key in sorted(ReachedFlows.facts("", unit.content.text, python=python)):
            WorkerFacts.add("reached.flow", key[1:])  # without the place: `_can_x` is `can_x`


class WorkerSummaries:
    """The worker's cross-file summaries of one unit (item 60), into `WorkerFacts`. Not a verdict
    feature: kept out of `WorkerAnalysis`, whose code the feature schema hashes."""

    #: TypeScript declaration files: `export * from "../x"` in one is a type's re-export, and read
    #: as the module's it made every Baileys release's join incomplete (lib/index.d.ts).
    DECLARATIONS: ClassVar[tuple[str, ...]] = (".d.ts", ".d.mts", ".d.cts")

    @staticmethod
    def declaration(path: str) -> bool:
        return path.rsplit("!", 1)[-1].lower().endswith(WorkerSummaries.DECLARATIONS)

    @staticmethod
    def produce(unit: Any) -> None:
        """A JavaScript file's cross-file summaries (item 60): what its exports do with their
        parameters and what it hands to the package's other modules, for the parent to join."""
        from cordon_scanner.analysis.javascript.flow.summaries import JsSummaries
        from cordon_scanner.analysis.javascript.js_flow import JsFlow
        from cordon_scanner.engine.isolation.facts import WorkerFacts

        if unit.language not in ("javascript", "typescript") or unit.content.is_binary:
            return
        if WorkerSummaries.declaration(unit.path):
            return  # types only: nothing in it runs, so it calls and re-exports nothing at run time
        facts = JsFlow.summaries(unit.content.text)
        for kind in JsSummaries.KINDS:
            for value in facts.get(kind, ()):
                WorkerFacts.add(kind, value)


class ParentAnalysis:
    """The parent's side: a file's facts as the steps read them."""

    @staticmethod
    def of(facts: dict[str, dict[str, list[Any]]], path: str) -> dict[str, list[Any]]:
        return facts.get(path, {})

    @staticmethod
    def labels(facts: dict[str, dict[str, list[Any]]], path: str) -> set[str] | None:
        """The capability names of a file, or None when its labelling raised or no worker sent any
        (a file the worker did not label: never one the parent would have)."""
        held = ParentAnalysis.of(facts, path)
        if held.get("cap.error"):
            return None
        return set(held.get("cap.label", ()))

    @staticmethod
    def runs_download(facts: dict[str, dict[str, list[Any]]], path: str) -> bool:
        return bool(ParentAnalysis.of(facts, path).get("cap.download"))

    @staticmethod
    def raised(facts: dict[str, dict[str, list[Any]]], path: str) -> bool:
        return bool(ParentAnalysis.of(facts, path).get("cap.error"))


__all__ = ["PROFILE_BYTES", "ParentAnalysis", "WorkerAnalysis", "WorkerSummaries"]
