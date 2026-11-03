"""What the code a consumer runs does with what it reads: the package verdict's flow facts.

The capability profile (`Engine._capability_profile`) says what the files an install or an import
runs can do -- reach the network, start a process. A library's entry point can do both and be
harmless; what it does with a secret is the question. These facts name each source a reached file
reads, the sink it reaches and the kind of destination (`JsFlow`): `import_flow_environment_
request_unknown` is the entry point sending the environment somewhere its file does not name.

Three places, each a key prefix; JavaScript is read by `JsFlow`, Python by `PythonFlowFacts`:

- `install`: the hook scripts and the files they run;
- `import`: the package's own entry points (`main`, `bin`, `exports`);
- `closure`: the first-party files those entry points load, transitively, and are not entries.

The framework facts name what the capability primitives cannot see in a plugin: an n8n node
reads its credentials through `this.getCredentials()` and sends through `helpers.request`, so
a credential stealer written as a node shows no credential read and no egress (review 98: one
family of five releases). A legitimate node makes the same calls -- 115 of the npm work set's
318 n8n nodes, 52 of them to a host their own credential definition does not name -- so these
are facts for the verdict to weigh, never a rule.

Nothing here blocks. The keys are new, so a model trained without them ignores them, and every
fact is a function of the files' bytes alone.
"""

from __future__ import annotations

import os
import re
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.analysis.javascript.js_flow import JsFlow
from cordon_scanner.analysis.python.py_flow_facts import PythonFlowFacts
from cordon_scanner.detect.binary.features import BinaryFeatures
from cordon_scanner.detect.code.features import CodeFeatures
from cordon_scanner.foundation.dependencies import HookKinds
from cordon_scanner.foundation.files.windows import BytesWindows, WindowSourceChanged

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping, Sequence

    from cordon_scanner.detect.base import FileUnit, ScanContext
    from cordon_scanner.detect.code.features import Source
    from cordon_scanner.foundation.models import Finding


class ReachedFlows:
    """`of(units, ctx)`: the flow and framework facts of the files a consumer runs."""

    #: Per place, as many files as the capability profile reads (`Engine._PROFILE_FILES`).
    FILES: ClassVar[int] = 50
    #: The size past which a file is not read here: the profile's own limit.
    MAX_SIZE: ClassVar[int] = 1_000_000

    FRAMEWORK: ClassVar[dict[str, re.Pattern[str]]] = {
        "framework_credential": re.compile(r"\.getCredentials\s*\("),
        "framework_request": re.compile(
            r"\bhelpers\s*\.\s*(?:request|httpRequest|httpRequestWithAuthentication)\s*\("
        ),
    }

    @staticmethod
    def places(ctx: ScanContext) -> dict[str, frozenset[str]]:
        entries = ctx.import_entry_paths
        return {
            "install": ctx.install_hook_paths | ctx.install_entry_paths,
            "import": entries,
            "closure": ctx.library_closure_paths - entries,
        }

    @staticmethod
    def readable(unit: FileUnit) -> bool:
        """A code file within the size this reads."""
        return unit.content.size <= ReachedFlows.MAX_SIZE and unit.path.rsplit("!", 1)[
            -1
        ].lower().endswith(ReachedFlows.CODE)

    @staticmethod
    def reads(unit: FileUnit, ctx: ScanContext) -> bool:
        """Whether `of` could read this file: in a place, and readable (the per-place file count is
        the parent's to apply, in its unit order)."""
        return ReachedFlows.readable(unit) and any(
            unit.path in paths for paths in ReachedFlows.places(ctx).values()
        )

    @staticmethod
    def of(
        units: Sequence[FileUnit], ctx: ScanContext, facts: dict[str, dict[str, list[Any]]]
    ) -> dict[str, float]:
        """`facts` holds each file's flow facts as its worker read them (`reached.flow`, item 56):
        the place is joined here, so nothing in this process reads a file."""
        out: dict[str, float] = {}
        for place, paths in ReachedFlows.places(ctx).items():
            read = 0
            for unit in units:
                if read >= ReachedFlows.FILES:
                    break
                if unit.path not in paths or not ReachedFlows.readable(unit):
                    continue
                read += 1
                for suffix in facts.get(unit.path, {}).get("reached.flow", ()):
                    out[f"{place}_{suffix}"] = 1.0
        if os.environ.get(ReachedFlows.MEASURE) == "1":
            out.update(CodeFeatures.of(ReachedFlows.sources(units, ctx)))
            out.update(BinaryFeatures.of(ReachedFlows.executables(units)))
        return out

    @staticmethod
    def executables(units: Sequence[FileUnit]) -> Iterator[tuple[int, Callable[[int, int], bytes]]]:
        """Every compiled program the package ships, wherever it sits, whole: an archive member
        or a large file is read from its window source, past the prefix every rule reads."""
        for unit in units:
            content = unit.content
            if BinaryFeatures.format_of(content.raw[:4]) is None:
                continue
            source = content.window_source
            if source is None:
                with BytesWindows(content.raw).reader() as read:
                    yield len(content.raw), read
                continue
            try:
                with source.reader() as read:
                    yield source.size, read
            except WindowSourceChanged:
                continue

    #: Set only by measurement runs (`reviews/review-98/tools/rescan_sample.py`'s containers): the
    #: code features (`CodeFeatures`) are computed for the scan records a model is trained on, and a
    #: user's scan neither computes nor reports them until a shipped model reads them.
    MEASURE: ClassVar[str] = "CORDON_MEASURE_FEATURES"
    CODE: ClassVar[tuple[str, ...]] = (".js", ".mjs", ".cjs", ".py")
    #: What the code features read besides: TypeScript a loader runs, and shell scripts.
    SOURCE: ClassVar[tuple[str, ...]] = (*CODE, ".ts", ".mts", ".cts", ".tsx", *CodeFeatures.SHELL)

    @staticmethod
    def sources(units: Sequence[FileUnit], ctx: ScanContext) -> dict[str, list[tuple[str, Source]]]:
        """Each place's code, as the code features read it: the install hooks' own command lines
        first (a `postinstall` is often the whole payload, and no file holds it), then every
        reached JavaScript, TypeScript, Python and shell file, whole. No count or size limit: a file
        past them -- one 27 MB bundle as a package's `main` -- is given as its windows, all of them,
        so nothing padded past a limit goes unread."""
        from cordon_scanner.ecosystems.registry import EcosystemRegistry

        out: dict[str, list[tuple[str, Source]]] = {}
        for place, paths in ReachedFlows.places(ctx).items():
            files: list[tuple[str, Source]] = []
            for unit in units:
                if unit.path not in paths or place != "install":
                    continue
                ecosystem = EcosystemRegistry.get(
                    EcosystemRegistry.manifest_ecosystem(unit.path) or ""
                )
                try:
                    hooks = ecosystem.parse_manifest(unit.content).hooks if ecosystem else ()
                except Exception:  # noqa: BLE001, S112
                    continue
                files += [
                    (f"{unit.path}#{hook.name}.sh", hook.command.encode())
                    for hook in hooks
                    if hook.command and not HookKinds.action_step(hook)
                ]
            for unit in units:
                if unit.path not in paths:
                    continue
                name = unit.path.rsplit("!", 1)[-1].lower()
                path = unit.path if name.endswith(ReachedFlows.SOURCE) else None
                if path is None and "." not in name.rsplit("/", 1)[-1]:
                    path = ReachedFlows._interpreted(unit.path, unit.content.raw[:128])
                if path is not None:
                    files.append((path, ReachedFlows._whole(unit)))
            out[place] = files
        return out

    @staticmethod
    def _whole(unit: FileUnit) -> Source:
        """The file's bytes, or -- held only as a prefix -- a callable reading all its windows."""
        source = unit.content.window_source
        if source is None:
            return unit.content.raw

        def windows() -> Iterator[bytes]:
            try:
                with source.reader() as read:
                    for offset in range(0, source.size, CodeFeatures.WINDOW):
                        yield read(offset, CodeFeatures.WINDOW)
            except WindowSourceChanged:
                return

        return windows

    _SHEBANG: ClassVar[re.Pattern[bytes]] = re.compile(
        rb"#![ \t]{0,8}\S{0,128}?(?:env[ \t]{1,8}(?:-\S{1,64}[ \t]{1,8}){0,4})?(node|python[0-9.]{0,8}|bash|sh|zsh|dash)\b"
    )

    @staticmethod
    def _interpreted(path: str, head: bytes) -> str | None:
        """An extensionless script -- a `bin` such as `bin/tool` -- named for the language its
        `#!` line runs it with, so the code features read it as that language."""
        match = ReachedFlows._SHEBANG.match(head)
        if match is None:
            return None
        interpreter = match.group(1).decode()
        suffix = ".js" if interpreter == "node" else ".py" if interpreter[:2] == "py" else ".sh"
        return path + "#" + suffix

    @staticmethod
    def language(path: str, head: bytes) -> str | None:
        """Which flow reader a file is read with, as `of` reads it: "py", "js", or None; an
        extensionless script by its `#!` line (the rule modules `js` and `python` use this)."""
        name = path.rsplit("!", 1)[-1].lower()
        if name.endswith(".py"):
            return "py"
        if name.endswith(ReachedFlows.CODE):
            return "js"
        if "." not in name.rsplit("/", 1)[-1]:
            named = ReachedFlows._interpreted(path, head[:128])
            if named is not None and named.endswith((".js", ".py")):
                return named[-2:]
        return None

    @staticmethod
    def facts(place: str, text: str, *, python: bool = False) -> dict[str, float]:
        """One file's facts under `place`: each source, sink and destination kind it joins, and
        the framework calls it makes."""
        out = {
            f"{place}_can_{name}": 1.0
            for name, pattern in ReachedFlows.FRAMEWORK.items()
            if pattern.search(text)
        }
        if python:
            for source, sink, destination in PythonFlowFacts.of(text):
                out[f"{place}_flow_{source}_{sink}_{destination}"] = 1.0
            return out
        try:
            flows = JsFlow.flows(text)
        except Exception:  # a fact is evidence, never a scan failure  # noqa: BLE001
            flows = []
        for flow in flows:
            for source in sorted(flow.sources):
                out[f"{place}_flow_{source}_{flow.sink}_{flow.destination}"] = 1.0
        return out


__all__ = ["CrossFileJoin", "ReachedFlows"]


class CrossFileJoin:
    """Item 60's parent half: the workers' summaries joined across the package, and what the
    re-grade needs to know of the join (note 78). Not part of the verdict's features: kept out of
    `ReachedFlows`, whose code the feature schema hashes (`FeatureSchema.EXTRACTOR`)."""

    @staticmethod
    def cross_file(
        units: Sequence[FileUnit], facts: Mapping[str, Mapping[str, list[Any]]]
    ) -> dict[str, tuple[tuple[int, tuple[str, ...], str, str], ...]]:
        """Item 60's join: per calling file, the flows into another of the package's files that a
        flow rule reports (`JS_FLOW_RULES`), composed from the workers' summaries (`js.*` facts,
        `CrossFile.compose`): set arithmetic over facts, never a file read here."""
        from cordon_scanner.analysis.javascript.flow.summaries import CrossFile, JsSummaries
        from cordon_scanner.detect.code.capability.javascript import JavaScriptCapabilities

        joined = {
            path: dict(held)
            for path, held in facts.items()
            if any(kind in held for kind in JsSummaries.KINDS)
        }
        if not joined:
            return {}
        rules = JavaScriptCapabilities.JS_FLOW_RULES
        out: dict[str, list[tuple[int, tuple[str, ...], str, str]]] = {}
        for path, line, sources, sink, dest in CrossFile.compose(
            joined, frozenset(u.path for u in units)
        ):
            if any(kind in sources and sink in sinks for kind, _rule, sinks in rules):
                out.setdefault(path, []).append((line, sources, sink, dest))
        return {path: tuple(found) for path, found in sorted(out.items())}

    @staticmethod
    def unresolved(
        facts: Mapping[str, Mapping[str, list[Any]]], findings: Sequence[Finding]
    ) -> bool:
        """Whether some file's calls into the package are not all known: a computed require, a file
        the analysis could not read whole, or a file whose facts were refused."""
        from cordon_scanner.analysis.javascript.flow.summaries import JsSummaries

        return any(
            JsSummaries.UNRESOLVED in held.get("js.require", ()) for held in facts.values()
        ) or any(f.rule_id == "OPERATIONAL.WORKER.FACTS_REFUSED" for f in findings)

    @staticmethod
    def lowered(findings: Sequence[Finding]) -> set[str]:
        """The files with a capability finding lowered as a parameter-built command (note 78)."""
        from cordon_scanner.detect.code.capability.grading import CompositeGrading

        reason = CompositeGrading.PARAMETER_COMMAND_REASON
        return {
            f.location.path
            for f in findings
            if f.detector == "capability"
            and any(reason in step for step in f.explanation.escalations)
        }
