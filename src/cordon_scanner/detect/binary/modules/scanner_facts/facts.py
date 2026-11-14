"""The scanner's facts as the `package`, `js` and `python` rule modules read them.

The facts are the package verdict's own: the capability profile and reached flows
(`Engine._capability_profile`, `detect/code/reached_flows`), the registry record
(`engine/pipeline/history`), and the campaign siblings (`detect/supply/campaign_sibling`). The
engine gathers them once, after detection (`engine/pipeline/facts`), into one plain mapping
carried on the scan context (`ScanContext.scan_facts`); a rule file importing one of these modules
is matched then, in a deferred pass. Nothing here analyses anything: it reads that mapping and the
context's path sets.

    scan_facts
      identity   [ecosystem, name, version], or None where the release is not named
      can        [[place, capability], ...]            the profile's  {place}_can_{capability}
      flows      [[place, source, sink, destination]]  the flows'     {place}_flow_{s}_{k}_{d}
      registry   the reg_* facts, or None: nothing acquired, or a content-only run
      campaign   {archive: [siblings, facets shared]}, for each npm manifest read
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.detect.binary.modules.values import Call, Module, Record, Scalar, Seq, Sig

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.detect.base import ScanContext
    from cordon_scanner.foundation.content import FileContent

INT, TEXT, BOOL = Scalar.INT, Scalar.TEXT, Scalar.BOOL


class ScanFacts:
    """Reads the gathered facts and the context's places for one file.

    A measurement run (`CORDON_MEASURE_FEATURES=1`, the marker `ReachedFlows.MEASURE` names) is
    content-only, the trainer's measure: the gathered facts then hold no registry record, so
    `package.registry.known` is false and every other registry field undefined, and no rule
    carries registry knowledge into a content-only number (`ScanFactsGathering.CONTENT_ONLY`)."""

    #: The modules that read the scanner's facts: a rule file importing one is matched after them.
    MODULES: ClassVar[frozenset[str]] = frozenset({"package", "js", "python"})

    @staticmethod
    def place(path: str, ctx: ScanContext) -> str:
        """Where the file runs: an agent's script (in the install-hook paths too, so first), an
        install hook or what it runs, a package entry point, the first-party files those load,
        a CI script, or nowhere a consumer or a machine runs on its own ("")."""
        if path in ctx.agent_run_paths:
            return "agent"
        if path in ctx.install_hook_paths or path in ctx.install_entry_paths:
            return "install"
        if path in ctx.import_entry_paths:
            return "import"
        if path in ctx.library_closure_paths:
            return "closure"
        if path in ctx.ci_hook_paths:
            return "ci"
        return ""

    @staticmethod
    def matches(wanted: Iterable[str], got: Iterable[str]) -> bool:
        """Each wanted part is the got part, or empty (any)."""
        return all(w in ("", g) for w, g in zip(wanted, got, strict=True))

    @staticmethod
    def text(value: Any) -> str:
        """A rule's text argument (bytes) as the facts hold it."""
        return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)


class FileFlows:
    """The `js` and `python` modules' shared reading: one source file's flows, by the package
    verdict's own reader for its language (`scanner_facts.js`, `scanner_facts.python`)."""

    SCHEMA: ClassVar[Record] = Record(
        {
            "place": TEXT,
            "flow": Call(Sig(("text", "text", "text"), BOOL)),
            "flows": INT,
            "sinks": Seq(TEXT),
        }
    )
    #: Outside a scan's deferred pass: every field undefined.
    EMPTY: ClassVar[Module] = Module(SCHEMA, lambda data: {})

    #: The reader's language (`ReachedFlows.language`).
    LANGUAGE: ClassVar[str] = ""

    @classmethod
    def module(cls, path: str, ctx: ScanContext, content: FileContent) -> Module:
        values = cls.values(path, ctx, content)
        return Module(FileFlows.SCHEMA, lambda data: values)

    @classmethod
    def values(cls, path: str, ctx: ScanContext, content: FileContent) -> dict[str, Any]:
        from cordon_scanner.detect.code.reached_flows import ReachedFlows

        if (
            content.size > ReachedFlows.MAX_SIZE
            or ReachedFlows.language(path, content.raw[:128]) != cls.LANGUAGE
        ):
            return {}
        # A reader that raises escapes to the rule-file pass's OPERATIONAL.RULEFILE.UNAVAILABLE,
        # which degrades coverage: rules that block read these facts (S2, reviews/release-080).
        flows = cls.read(content.text)
        t = ScanFacts.text
        sinks = sorted({sink for _, sink, _ in flows})
        return {
            "place": ScanFacts.place(path, ctx).encode(),
            "flow": (lambda *wanted: any(ScanFacts.matches(map(t, wanted), f) for f in flows),),
            "flows": len(flows),
            "sinks": {i: s.encode() for i, s in enumerate(sinks)},
        }

    @staticmethod
    def read(text: str) -> list[tuple[str, str, str]]:
        """The file's flows as (source, sink, destination)."""
        raise NotImplementedError


__all__ = ["FileFlows", "ScanFacts"]
