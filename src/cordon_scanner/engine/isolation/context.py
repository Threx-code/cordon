"""The scan context built in a supervised worker (item 56, phase (b)): the parent parses no manifest,
lockfile, SBOM, hook or closure.

Everything between the walk and the finished `ScanContext` parses scanned content: the hooks written
inline, the deobfuscation lift, the dependency graph (manifests, lockfiles, an SBOM target,
.gitmodules), the hook paths and their import and require closures, the skill and server sources. It
runs here, in one worker per scan under item 28's bounds, as the very same steps the parent ran, and
comes back as one JSON document the parent checks before it believes any of it:

```
  parent                                            context worker (template fork, or spawned)
  ──────                                            ──────────────────────────────────────────
  units as work items (path, sha256, carried       re-reads each unit (the hash must match), runs
  bytes or the path that opens it, language) ────► the steps, encodes what they produced
       ◄── ContextFacts: one JSON document ────────
  ContextFacts.accept: bounded before decoding, every key declared, every value its declared type,
  every path a unit of the scan's; refused = OPERATIONAL.WORKER.CONTEXT_FAILED, never a retry here
```

A worker that dies, hangs, overruns, raises or answers with a refused document leaves the scan with
only what the walk gives (`tree_paths`), and a blocking gap at the scan's scope: incomplete scans
block (item 27). The parent never runs a step in-process. `IsolationUnavailable` is never caught.
"""

from __future__ import annotations

import dataclasses
import json
import re
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.engine.isolation.records import LIST_ENTRIES, Codec
from cordon_scanner.foundation.models import Severity
from cordon_scanner.foundation.results import Dependency, OperationalFinding

if TYPE_CHECKING:
    from cordon_scanner.detect.base import FileUnit, ScanContext
    from cordon_scanner.engine.engine import Engine
    from cordon_scanner.engine.pipeline.accumulator import Accumulator

DOCUMENT_BYTES = 64 << 20
"""The largest document a context worker may answer with."""
MAX_DEPTH = 12
"""The deepest the document nests: its sections, a list, a record, a finding's own nesting (its
location, evidence, explanation and risk), and slack. Checked before decoding (`Facts.depth`)."""

PATH_SETS = (
    "install_hook_paths",
    "startup_closure_paths",
    "import_entry_paths",
    "library_entry_paths",
    "library_closure_paths",
    "install_entry_paths",
    "agent_run_paths",
    "ci_hook_paths",
    "tree_paths",
    "shipped_native_paths",
    "consumer_install_paths",
    "import_closure_paths",
)
"""Context fields that are sets of tree paths: each must be a path of the scan's units, or one the
parent's own context held before the worker ran (the inventory's hook paths)."""
NAME_SETS = ("declared_dependencies", "verdict_dependency_names")
"""Context fields that are sets of dependency names."""
SCALARS: dict[str, type] = {
    "package_distribution": bool,
    "package_repository": str,
    "distribution": str,
    "confusion_version": str,
}
DEFERRED_LINES = ("install_deferred_lines", "import_deferred_lines", "startup_deferred_lines")
"""Context fields that are `(path, first_line, last_line)` sets: bodies a hook or an import never runs."""
RUNNER_MAPS = (
    "python_imported_runners",
    "python_carried_calls",
    "python_imported_collectors",
    "python_sent_names",
)
"""Context fields that are `{path: {function: "0,2"}}`: the positions of the parameters it runs
(for `python_sent_names`, `{path: {name: "3"}}`: how many other files send the name)."""
CLIENT_MAPS = ("python_imported_clients",)
"""Context fields that are `{path: {name: client constructor}}`: crossing as `[path, name, client]`
triples, each path one of the scan's units, each name an identifier, each client one of
`HTTP_CLIENTS`."""
CONTEXT_FIELDS = (
    *PATH_SETS,
    *NAME_SETS,
    *SCALARS,
    *DEFERRED_LINES,
    *CLIENT_MAPS,
    *RUNNER_MAPS,
    "dependencies",
)
"""Every context field a context worker may set. A step that changes any other field fails the
worker (`ContextWork.encode_context`): a new field is declared here, with its shape, or not sent."""


class ContextWork:
    """The worker's side: the parent's steps, run here, and what they produced, encoded."""

    STEP_RULE = "OPERATIONAL.WORKER.CONTEXT_STEP_FAILED"

    @staticmethod
    def run(item: tuple[str, list[Any], str, str, str, bool, Any]) -> str:
        """One scan's context, as a JSON document. `item` is the kind ("tree" or "archive"), the
        units as work items, the root a walked unit is read under, the scan's root, the place a
        step's failure is reported at, whether the archive is an image, and the inventory's held
        manifest-hook places.

        Each step runs in its own guard (note 56's review, change 1): one that raises is that step's
        blocking gap, and the steps after it still run. In the order of what blocks (change 2): the
        inventory's manifest hooks, the hooks written inline, the lift (the closures read lifted
        units), what runs at install and its closures, and only then the dependency graph."""
        from cordon_scanner.engine.pipeline.hooks import JsReferences

        kind, items, read_root, scan_root, where, image, pending = item
        run = ContextRun(kind, items, read_root, where)
        before = run.ctx
        if pending is not None:
            # The manifests' hooks the inventory held a place for: everything after reads the hook
            # paths they give, and a file a hook runs takes the hook's language.
            found = run.guarded(
                "inventory hooks", lambda: ContextWork.inventory_hooks(run.engine, pending), None
            )
            if found is not None:
                run.inventory_hooks = found
                run.ctx = ContextWork.with_hooks(run.engine, run.ctx, run.units, run.walked, found)
        if kind == "tree":
            run.tree(Path(scan_root))
        else:
            run.archive(image)
        units = run.units
        manifests, documents = run.guarded(
            "manifests", lambda: ContextWork.documents(units), ([], [])
        )
        references = run.guarded("JavaScript references", lambda: JsReferences.of(units), {})
        document = run.document(before, items) | {
            "manifests": manifests,
            "documents": documents,
            "js_references": references,
        }
        return json.dumps(document, separators=(",", ":"), allow_nan=False)

    @staticmethod
    def documents(units: list[FileUnit]) -> tuple[list[Any], list[Any]]:
        """Every manifest-shaped unit's records and every JSON-shaped unit's documents, encoded."""
        from types import MappingProxyType

        from cordon_scanner.ecosystems.registry import EcosystemRegistry
        from cordon_scanner.engine.isolation.documents import JSON_SUFFIXES
        from cordon_scanner.engine.pipeline.graph import Graph, ParsedManifests
        from cordon_scanner.foundation.formats.scanned_json import ScannedJson
        from cordon_scanner.foundation.formats.served_json import ServedJson

        view = MappingProxyType({u.path: u.content for u in units})
        manifests: list[Any] = []
        documents: list[Any] = []
        seen: set[str] = set()
        for unit in units:
            ecosystem_id = EcosystemRegistry.manifest_ecosystem(unit.path)
            ecosystem = EcosystemRegistry.get(ecosystem_id) if ecosystem_id else None
            if ecosystem is not None and ecosystem_id is not None:
                kinds = ["alone"]
                if getattr(ecosystem, "parse_in_tree", None) is not None:
                    kinds.append("tree")
                for kind in kinds:
                    try:
                        record = (
                            ParsedManifests.manifest_alone(ecosystem, unit)
                            if kind == "alone"
                            else Graph.manifest_of(ecosystem, unit, view)
                        )
                        manifests.append(
                            [ecosystem_id, unit.path, kind, Codec.encode(record), None]
                        )
                    except Exception as exc:  # noqa: BLE001 - the parse's outcome, as the parent saw it
                        manifests.append([ecosystem_id, unit.path, kind, None, type(exc).__name__])
            if unit.content.is_binary or not (
                ecosystem is not None or unit.path.lower().endswith(JSON_SUFFIXES)
            ):
                continue
            # The three forms the parent's steps hand the decoder: the text, the bytes, and the bytes
            # decoded with replacement (`InstallScripts.of`).
            raw = unit.content.raw
            for form in (unit.content.text, raw, raw.decode("utf-8", "replace")):
                key = ServedJson.key(form)
                if key in seen:
                    continue
                seen.add(key)
                try:
                    value = ScannedJson.loads(form)
                except (ValueError, RecursionError) as exc:
                    documents.append([key, unit.path, None, type(exc).__name__])
                    continue
                # JSON text, or flat tokens past DOCUMENT_DEPTH: any depth crosses, none recursively.
                documents.append([key, unit.path, ServedJson.encode(value), ""])
        return manifests, documents

    @staticmethod
    def inventory_hooks(engine: Any, pending: Any) -> list[Any]:
        """The inventory's hooks, each held place read as `Engine._manifest_hooks` read it, in the
        walk's order, then kept where they execute (`Hooks.hook_executes`), as `inventory` keeps them."""
        from cordon_scanner.engine.isolation.documents import PendingHooks
        from cordon_scanner.engine.pipeline.hooks import Hooks

        held, package_directories, seen = pending
        hooks: list[Any] = []
        for entry in held:
            if isinstance(entry, PendingHooks):
                hooks.extend(
                    engine._manifest_hooks(
                        Path(entry.real_path),
                        entry.rel_path,
                        entry.ecosystem,
                        seen if entry.in_tree else None,
                    )
                )
            else:
                hooks.append(entry)
        return [h for h in hooks if Hooks.hook_executes(h, package_directories)]

    @staticmethod
    def with_hooks(
        engine: Any, ctx: ScanContext, units: list[FileUnit], walked: int, hooks: list[Any]
    ) -> ScanContext:
        """The context `Engine._context` builds from the inventory with these hooks, and each walked
        unit's language as `Units.read` gives it when a hook runs it (`Units.language_of`)."""
        from types import SimpleNamespace

        from cordon_scanner.engine.pipeline.hooks import Hooks
        from cordon_scanner.engine.pipeline.units import Units

        if ctx.repository is None:
            return ctx
        repository = replace(ctx.repository, hooks=tuple(hooks))
        before = Hooks.languages_from_hooks(ctx.repository)
        after = Hooks.languages_from_hooks(repository)
        for index in range(walked):
            unit = units[index]
            if before.get(unit.path) != after.get(unit.path):
                entry = SimpleNamespace(rel_path=unit.path)
                units[index] = replace(unit, language=Units.language_of(entry, after, unit.content))  # type: ignore[arg-type]
        fresh = engine._context(repository, deadline=ctx.deadline)
        return replace(
            ctx,
            repository=repository,
            install_hook_paths=fresh.install_hook_paths,
            ci_hook_paths=fresh.ci_hook_paths,
        )

    @staticmethod
    def encode_context(before: ScanContext, after: ScanContext) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for f in dataclasses.fields(after):
            value = getattr(after, f.name)
            if f.name == "repository" or value == getattr(before, f.name):
                # The inventory crosses as its hooks (`inventory_hooks`), never whole.
                continue
            if f.name not in CONTEXT_FIELDS:
                raise TypeError(f"a context step set {f.name}, which no context worker may send")
            if f.name == "dependencies":
                out[f.name] = [Codec.encode(d) for d in value]
            elif f.name in DEFERRED_LINES:
                out[f.name] = sorted([path, first, last] for path, first, last in value)
            elif f.name in SCALARS:
                out[f.name] = value
            elif f.name in (*CLIENT_MAPS, *RUNNER_MAPS):
                out[f.name] = sorted(
                    [path, name, client]
                    for path, names in (value or {}).items()
                    for name, client in names.items()
                )
            else:
                out[f.name] = sorted(value)
        return out


class ContextRun:
    """One context worker's scan: its units read again, its accumulator, and the steps' outcomes."""

    def __init__(self, kind: str, items: list[Any], read_root: str, where: str) -> None:
        from cordon_scanner.detect.base import FileUnit
        from cordon_scanner.engine.parallel import ParallelScanner
        from cordon_scanner.engine.pipeline.accumulator import Accumulator
        from cordon_scanner.engine.progress import NullProgress

        state = ParallelScanner._worker
        if state is None:
            raise RuntimeError("the context worker has no scan state")
        self.engine, self.ctx, self.where = state.engine, state.context, where
        self.engine._scanning_archive = kind == "archive"
        # The parent draws the progress line; a worker writing to the same terminal would tear it.
        for holder in (self.engine, self.engine.stages, self.engine.archive_stages):
            holder.progress = NullProgress()
        self.units: list[FileUnit] = []
        for path, expected, carried, language, project, opens in items:
            content = ParallelScanner._read_item(path, expected, carried, self.engine, read_root)
            if content is None:
                # Not the bytes the parent read: the context would be about another tree.
                raise ValueError(f"{path} could not be read again as the parent read it")
            self.units.append(
                FileUnit(content=content, language=language, project=project, opens=opens)
            )
        self.walked = len(self.units)
        self.acc = Accumulator(finding_cap=self.engine.config.limits.max_findings)
        self.dependencies: tuple[Dependency, ...] = ()
        self.ingested: tuple[Dependency, ...] = ()
        self.inventory_hooks: Any = None
        self.archive_graph: Any = None

    def guarded(self, step: str, run: Any, fallback: Any) -> Any:
        try:
            return run()
        except Exception as exc:  # noqa: BLE001 - a step's failure is its own gap, named
            self.acc.incomplete(
                OperationalFinding.build(
                    path=self.where,
                    rule_id=ContextWork.STEP_RULE,
                    message=f"A step of working out what runs did not finish ({step}: "
                    f"{type(exc).__name__}). What it would have found is unknown.",
                    remediation="Rescan; if it recurs, report it with the package.",
                    severity=Severity.HIGH,
                )
            )
            return fallback

    def tree(self, root: Path) -> None:
        from cordon_scanner.engine.pipeline.graph import Graph

        engine, units, acc = self.engine, self.units, self.acc
        units.extend(self.guarded("inline hooks", lambda: engine.units.inline_hooks(units), []))
        units.extend(
            self.guarded("content language", lambda: engine.units.content_readings(units), [])
        )
        units.extend(self.guarded("deobfuscation", lambda: engine.units.deobfuscated(units), []))
        ctx = self.ctx
        self.ctx = self.guarded(
            "install context",
            lambda: engine.stages.install_context(units, acc, ctx, ()),
            replace(ctx, tree_paths=frozenset(u.path for u in units)),
        )
        self.dependencies, self.ingested = self.guarded(
            "dependencies", lambda: engine.stages.dependencies(units, acc, root), ((), ())
        )
        if self.dependencies:
            self.ctx = replace(self.ctx, dependencies=Graph.packages(self.dependencies))

    def archive(self, image: bool) -> None:
        """The archive's context, then its graph, which the parent reads after detection
        (`ArchiveStages.dependencies`): built into an accumulator of its own, so the parent applies
        what it found at that same point and its findings keep their order."""
        from cordon_scanner.engine.package_format import PackageFormat
        from cordon_scanner.engine.pipeline.accumulator import Accumulator

        engine, units, acc, ctx = self.engine, self.units, self.acc, self.ctx
        self.ctx = self.guarded(
            "install context",
            lambda: engine.archive_stages.context(units, acc, ctx, None),
            replace(ctx, tree_paths=frozenset(u.path for u in units)),
        )
        graph_acc = Accumulator(finding_cap=engine.config.limits.max_findings)

        def archive_graph() -> tuple[Dependency, ...]:
            published = "" if image else PackageFormat.of(units)
            return tuple(engine.dependencies.build(units, graph_acc, published=published))

        built = self.guarded("dependencies", archive_graph, None)
        if built is not None:
            self.archive_graph = {
                "dependencies": [Codec.encode(d) for d in built],
                "findings": [f.to_dict() for f in graph_acc.findings],
                "complete": graph_acc.complete,
                "gaps": [list(gap) for gap in graph_acc.content_gaps],
                "not_installed": [Codec.encode(d) for d in graph_acc.not_installed],
            }

    def document(self, before: ScanContext, items: list[Any]) -> dict[str, Any]:
        from cordon_scanner.engine.pipeline.graph import ParsedManifests

        units, acc = self.units, self.acc
        hooks = self.inventory_hooks
        return {
            "languages": [
                [index, unit.language]
                for index, unit in enumerate(units[: self.walked])
                if unit.language != items[index][3]
            ],
            "added": [
                [unit.path, unit.content.text, unit.language, unit.project]
                for unit in units[self.walked :]
            ],
            "context": ContextWork.encode_context(before, self.ctx),
            "dependencies": [Codec.encode(d) for d in self.dependencies],
            "ingested": [Codec.encode(d) for d in self.ingested],
            "sbom_listed": [
                [path, Codec.encode(listed), purl, name, version, tool]
                for path, listed, purl, name, version, tool in self.engine._sbom_listed
            ],
            "findings": [f.to_dict() for f in acc.findings],
            "complete": acc.complete,
            "gaps": [list(gap) for gap in acc.content_gaps],
            "not_installed": [Codec.encode(d) for d in acc.not_installed],
            "raised": ParsedManifests.raised(),
            "archive_dependencies": self.archive_graph,
            "inventory_hooks": None if hooks is None else [Codec.encode(h) for h in hooks],
        }


@dataclasses.dataclass(slots=True)
class Accepted:
    """A context worker's document, checked and rebuilt."""

    languages: dict[int, str | None]
    added: list[tuple[str, str, str | None, str | None]]
    context: dict[str, Any]
    dependencies: tuple[Dependency, ...]
    ingested: tuple[Dependency, ...]
    sbom_listed: list[tuple[str, Any, str, str, str | None, str]]
    findings: list[Any]
    complete: bool
    gaps: list[tuple[str, str]]
    not_installed: list[Dependency]
    raised: dict[str, str]
    archive_dependencies: tuple[tuple[Dependency, ...], list[Any], bool, list[tuple[str, str]],
                                list[Dependency]] | None  # fmt: skip
    inventory_hooks: tuple[Any, ...] | None


class Refused(ValueError):
    """Why a context worker's document is refused."""


class ContextFacts:
    """The parent's side: what it accepts from a context worker, and nothing else."""

    LANGUAGE: ClassVar[re.Pattern[str]] = re.compile(r"[a-z0-9][a-z0-9+#._-]{0,63}")

    SECTIONS: ClassVar[frozenset[str]] = frozenset({
        "languages", "added", "context", "dependencies", "ingested", "sbom_listed", "findings",
        "complete", "gaps", "not_installed", "raised", "manifests", "documents",
        "archive_dependencies", "inventory_hooks", "js_references",
    })  # fmt: skip
    LISTS: ClassVar[frozenset[str]] = SECTIONS - {
        "complete", "context", "raised", "archive_dependencies", "inventory_hooks", "js_references",
    }  # fmt: skip

    @staticmethod
    def accept(
        text: str, units: list[FileUnit], before: ScanContext
    ) -> tuple[Accepted | None, str]:
        """The document, decoded and checked against the scan's units, or None with why it was
        refused. Plain data only: `json.loads` builds strings, numbers, booleans, None, lists and
        dicts, and each record is rebuilt field by field (`Codec.decode`)."""
        from cordon_scanner.engine.isolation.documents import Documents

        try:
            doc = ContextFacts._decoded(text, sum(len(u.content.raw) for u in units))
            languages = ContextFacts._languages(doc["languages"], len(units))
            known = {unit.path for unit in units}
            added = ContextFacts._added(doc["added"], known)
            hooks = ContextFacts._hooks(doc["inventory_hooks"])
            # A hook names a path the walk found, which need not be a unit read (an excluded file):
            # the hook sets are believed for the paths the inventory's hooks give, as `_context` does.
            context, why = ContextFacts._context(
                doc["context"], known | {h.path for h in hooks or ()}, before
            )
            if context is None:
                raise Refused(why)
            accepted = Accepted(
                languages=languages,
                added=added,
                context=context,
                dependencies=tuple(ContextFacts._records(doc["dependencies"])),
                ingested=tuple(ContextFacts._records(doc["ingested"])),
                sbom_listed=ContextFacts._listed(doc["sbom_listed"], known),
                findings=ContextFacts._found(doc["findings"], known),
                complete=ContextFacts._coverage(doc["complete"], doc["gaps"]),
                gaps=[(rule, path) for rule, path in doc["gaps"]],
                not_installed=ContextFacts._records(doc["not_installed"]),
                raised=ContextFacts._raised(doc["raised"]),
                archive_dependencies=ContextFacts._graph(doc["archive_dependencies"], known),
                inventory_hooks=hooks,
            )
            why = Documents.accept(doc["manifests"], doc["documents"], doc["js_references"], known)
            if why:
                raise Refused(why)
        except Refused as refused:
            return None, str(refused)
        return accepted, ""

    @staticmethod
    def _decoded(text: str, scanned: int = 0) -> dict[str, Any]:
        """The document decoded and its sections checked. Its size is bounded by DOCUMENT_BYTES plus
        six times the bytes the scan read (a deep document crosses as tokens, several times its text)."""
        from cordon_scanner.foundation.formats.served_json import ServedJson

        bound = DOCUMENT_BYTES + 6 * scanned
        if len(text) > bound:
            raise Refused(f"{len(text)} bytes, past the {bound} this scan's context may take")
        if ServedJson.depth(text) > MAX_DEPTH:
            raise Refused("a document nested past its declared shape")
        try:
            doc = json.loads(text)
        except (ValueError, RecursionError, MemoryError):
            raise Refused("a document that is not JSON within the decoder's limits") from None
        if not isinstance(doc, dict) or set(doc) != ContextFacts.SECTIONS:
            raise Refused("a document whose sections are not the declared ones")
        for name in ContextFacts.LISTS:
            if not isinstance(doc[name], list) or len(doc[name]) > LIST_ENTRIES:
                raise Refused(f"{name} is not a list within {LIST_ENTRIES} entries")
        return doc

    @staticmethod
    def _languages(entries: list[Any], count: int) -> dict[int, str | None]:
        languages: dict[int, str | None] = {}
        for entry in entries:
            if not (
                isinstance(entry, list)
                and len(entry) == 2
                and type(entry[0]) is int
                and 0 <= entry[0] < count
                and (entry[1] is None or ContextFacts._language(entry[1]))
            ):
                raise Refused("a language change of the wrong shape")
            languages[entry[0]] = entry[1]
        return languages

    @staticmethod
    def _added(
        entries: list[Any], known: set[str]
    ) -> list[tuple[str, str, str | None, str | None]]:
        """The derived units; `known` grows by each. A derived unit is named after the file it came
        from (`#deobfuscated.js`, an inline hook's `#<hook>`): never a name the walk gave a file."""
        added: list[tuple[str, str, str | None, str | None]] = []
        for entry in entries:
            if not (
                isinstance(entry, list)
                and len(entry) == 4
                and isinstance(entry[0], str)
                and ("#" in entry[0] or "!" in entry[0])
                and entry[0] not in known
                and len(entry[0]) <= 4096
                and isinstance(entry[1], str)
                and (entry[2] is None or ContextFacts._language(entry[2]))
                and (entry[3] is None or (isinstance(entry[3], str) and len(entry[3]) <= 4096))
            ):
                raise Refused("a derived unit of the wrong shape")
            known.add(entry[0])
            added.append((entry[0], entry[1], entry[2], entry[3]))
        return added

    @staticmethod
    def _hooks(entries: Any) -> tuple[Any, ...] | None:
        from cordon_scanner.foundation.models import Hook

        if entries is None:
            return None
        if not isinstance(entries, list) or len(entries) > LIST_ENTRIES:
            raise Refused("inventory hooks of the wrong shape")
        hooks = [Codec.decode(Hook, h) for h in entries]
        if any(h is None for h in hooks):
            raise Refused("an inventory hook of the wrong shape")
        return tuple(hooks)

    @staticmethod
    def _records(entries: Any) -> list[Dependency]:
        if not isinstance(entries, list) or len(entries) > LIST_ENTRIES:
            raise Refused("dependency records of the wrong shape")
        out = [Codec.decode(Dependency, d) for d in entries]
        if any(d is None for d in out):
            raise Refused("a dependency record of the wrong shape")
        return out

    @staticmethod
    def _listed(
        entries: list[Any], known: set[str]
    ) -> list[tuple[str, Any, str, str, str | None, str]]:
        from cordon_scanner.engine.sbom_ingest import ListedVulnerability

        listed: list[tuple[str, Any, str, str, str | None, str]] = []
        for entry in entries:
            ok = isinstance(entry, list) and len(entry) == 6
            vulnerability = Codec.decode(ListedVulnerability, entry[1]) if ok else None
            if not (
                ok
                and vulnerability is not None
                and entry[0] in known
                and all(isinstance(entry[k], str) for k in (2, 3, 5))
                and (entry[4] is None or isinstance(entry[4], str))
            ):
                raise Refused("a listed vulnerability of the wrong shape")
            listed.append((entry[0], vulnerability, entry[2], entry[3], entry[4], entry[5]))
        return listed

    @staticmethod
    def _found(entries: Any, known: set[str]) -> list[Any]:
        from cordon_scanner.engine.cache import ScanCache

        if not isinstance(entries, list) or len(entries) > LIST_ENTRIES:
            raise Refused("findings of the wrong shape")
        out = []
        for data in entries:
            try:
                finding = ScanCache.finding_from_dict(data)
            except Exception:  # noqa: BLE001 - any malformed finding refuses the document
                raise Refused("a finding of the wrong shape") from None
            if finding.location.path not in known and finding.location.path != ".":
                raise Refused("a finding about a file the scan does not hold")
            out.append(finding)
        return out

    @staticmethod
    def _coverage(complete: Any, gaps: Any) -> bool:
        if not (
            type(complete) is bool
            and isinstance(gaps, list)
            and len(gaps) <= LIST_ENTRIES
            and all(
                isinstance(g, list) and len(g) == 2 and all(isinstance(x, str) for x in g)
                for g in gaps
            )
        ):
            raise Refused("coverage of the wrong shape")
        return complete

    @staticmethod
    def _raised(raised: Any) -> dict[str, str]:
        if (
            not isinstance(raised, dict)
            or len(raised) > LIST_ENTRIES
            or not all(
                isinstance(k, str) and isinstance(v, str) and len(v) <= 4096
                for k, v in raised.items()
            )
        ):
            raise Refused("manifest failures of the wrong shape")
        return raised

    @staticmethod
    def _graph(graph: Any, known: set[str]) -> Any:
        if graph is None:
            return None
        if not isinstance(graph, dict) or set(graph) != {
            "dependencies", "findings", "complete", "gaps", "not_installed",
        }:  # fmt: skip
            raise Refused("an archive graph of the wrong shape")
        complete = ContextFacts._coverage(graph["complete"], graph["gaps"])
        return (
            tuple(ContextFacts._records(graph["dependencies"])),
            ContextFacts._found(graph["findings"], known),
            complete,
            [(rule, path) for rule, path in graph["gaps"]],
            ContextFacts._records(graph["not_installed"]),
        )

    @staticmethod
    def _language(value: Any) -> bool:
        return isinstance(value, str) and ContextFacts.LANGUAGE.fullmatch(value) is not None

    @staticmethod
    def _context(
        data: Any, known: set[str], before: ScanContext
    ) -> tuple[dict[str, Any] | None, str]:
        if not isinstance(data, dict) or not set(data) <= set(CONTEXT_FIELDS):
            return None, "a context field no context worker may set"
        out: dict[str, Any] = {}
        for name, value in data.items():
            if name in SCALARS:
                if type(value) is not SCALARS[name] or (
                    isinstance(value, str) and len(value) > 4096
                ):
                    return None, f"{name} of the wrong type"
                out[name] = value
            elif name == "dependencies":
                records = (
                    [Codec.decode(Dependency, d) for d in value]
                    if isinstance(value, list)
                    else [None]
                )
                if any(d is None for d in records) or len(records) > LIST_ENTRIES:
                    return None, "a dependency record of the wrong shape"
                out[name] = tuple(records)
            elif name in DEFERRED_LINES:
                if not isinstance(value, list) or len(value) > LIST_ENTRIES or not all(
                    isinstance(t, list) and len(t) == 3 and t[0] in known
                    and type(t[1]) is int and type(t[2]) is int and 0 <= t[1] <= t[2]
                    for t in value
                ):  # fmt: skip
                    return None, f"{name} of the wrong shape"
                out[name] = frozenset((p, first, last) for p, first, last in value)
            elif name in RUNNER_MAPS:
                if not isinstance(value, list) or len(value) > LIST_ENTRIES or not all(
                    isinstance(t, list) and len(t) == 3 and t[0] in known
                    and isinstance(t[1], str) and len(t[1]) <= 256 and t[1].isidentifier()
                    and isinstance(t[2], str) and re.fullmatch(r"\d{1,3}(,\d{1,3}){0,255}", t[2])
                    for t in value
                ):  # fmt: skip
                    return None, f"{name} of the wrong shape"
                runners: dict[str, dict[str, str]] = {}
                for path, function, positions in value:
                    runners.setdefault(path, {})[function] = positions
                out[name] = runners or None
            elif name in CLIENT_MAPS:
                from cordon_scanner.analysis.python.flows.http_clients import HTTP_CLIENTS

                if not isinstance(value, list) or len(value) > LIST_ENTRIES or not all(
                    isinstance(t, list) and len(t) == 3 and t[0] in known
                    and isinstance(t[1], str) and len(t[1]) <= 256 and t[1].isidentifier()
                    and t[2] in HTTP_CLIENTS
                    for t in value
                ):  # fmt: skip
                    return None, f"{name} of the wrong shape"
                clients: dict[str, dict[str, str]] = {}
                for path, client_name, client in value:
                    clients.setdefault(path, {})[client_name] = client
                out[name] = clients or None
            else:
                if (
                    not isinstance(value, list)
                    or len(value) > LIST_ENTRIES
                    or not all(isinstance(x, str) and len(x) <= 4096 for x in value)
                ):
                    return None, f"{name} of the wrong shape"
                held = getattr(before, name)
                if name in PATH_SETS and not all(x in known or x in held for x in value):
                    return None, f"{name} names a path the scan does not hold"
                out[name] = frozenset(value)
        if "tree_paths" in out and out["tree_paths"] != frozenset(known):
            return None, "tree_paths that are not the scan's units"
        return out, ""


class ContextStage:
    """The parent's step: the context worker run, its answer applied, or the gap that says why not."""

    #: What the context worker may use (item 28's bounds): the detection pool's, for one unit the
    #: size of the whole scan, and the scan's own deadline over it (`Supervisor.deadline`).
    RULE = "OPERATIONAL.WORKER.CONTEXT_FAILED"

    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self.archive_graph: Any = None

    def build(
        self,
        kind: str,
        units: list[FileUnit],
        acc: Accumulator,
        ctx: ScanContext,
        root: Path,
        *,
        carry_content: bool,
        where: str,
        image: Any = None,
        pending_hooks: Any = None,
    ) -> tuple[ScanContext, tuple[Dependency, ...], tuple[Dependency, ...]]:
        """`units` extended with the derived units and their languages set, the context, the
        dependency graph and the ingested SBOM's records (a tree's; an archive's graph is built
        with it and applied after detection, `archive_dependencies`). An archive that is an image
        has it set on the context here: the worker never holds the image."""
        accepted, why = self._answer(
            kind, units, ctx, root, carry_content, where, image is not None, pending_hooks
        )
        # Members of an import library, marked in this process (the worker's units are rebuilt from
        # paths and bytes, so it cannot know them): only the polyglot name check reads it (notes/75).
        marked = frozenset(u.path for u in units if u.import_library)
        if accepted is None:
            ctx = replace(self._failed(units, acc, ctx, where, why), import_library_paths=marked)
            return (replace(ctx, image=image) if image is not None else ctx), (), ()
        ctx = replace(self._apply(accepted, units, acc, ctx), import_library_paths=marked)
        return (
            replace(ctx, image=image) if image is not None else ctx,
            accepted.dependencies,
            accepted.ingested,
        )

    @staticmethod
    def report_unread(acc: Accumulator) -> None:
        """What a step could not read, as gaps: manifests whose parse raised, and what the context
        worker did not return."""
        from cordon_scanner.engine.isolation.documents import Documents
        from cordon_scanner.engine.pipeline.graph import ParsedManifests

        ParsedManifests.report_raised(acc)
        Documents.report_missing(acc)

    def archive(
        self, units: list[FileUnit], acc: Accumulator, ctx: ScanContext, path: Path, image: Any
    ) -> ScanContext:
        """`build` for an archive target: its members' bytes always travel (no file to reopen)."""
        return self.build(
            "archive", units, acc, ctx, path, carry_content=True, where=path.name, image=image
        )[0]

    def _answer(
        self, kind: str, units: list[FileUnit], ctx: ScanContext, root: Path,
        carry_content: bool, where: str, image: bool, pending_hooks: Any,
    ) -> tuple[Accepted | None, str]:  # fmt: skip
        """The context worker run over `units`, and its document checked, or why there is none."""
        from cordon_scanner.engine.isolation.context_cache import ContextCache
        from cordon_scanner.engine.isolation.supervisor import Supervisor, Unit
        from cordon_scanner.engine.parallel import CARRIED_SETTINGS, ParallelScanner

        items = [
            (
                unit.path,
                unit.content.sha256,
                unit.content.carried
                if carry_content or "!" in unit.path or "#" in unit.path
                else unit.opens,
                unit.language,
                unit.project,
                unit.opens,
            )
            for unit in units
        ]
        read_root = str(root.parent if root.is_file() else root)
        module = f"{ParallelScanner.__module__}:ParallelScanner"
        template = getattr(self.engine, "_template", None)
        config, facts = self.engine.config, ctx.facts()
        setup: tuple[str, tuple[Any, ...]]
        if template is not None:
            setup = (f"{module}._prepare", ((), ctx.repository, facts))
        else:
            operator = {key: getattr(config, key) for key in CARRIED_SETTINGS}
            setup = (
                f"{module}._initialise",
                (type(self.engine), config.to_dict(), read_root, (), ctx.repository, operator,
                 facts),
            )  # fmt: skip
        item = (kind, items, read_root, str(root), where, image, pending_hooks)
        cache = self.engine.cache
        digest = self.cache_digest(item, ctx) if cache.enabled else ""
        if digest:
            # The same tree, scanned again: the worker's document from last time, checked exactly
            # as a fresh one is. A warm 20,000-file scan spent 10 s re-reading every file here.
            cached = ContextCache.get(cache, digest, DOCUMENT_BYTES)
            if cached is not None:
                accepted, why = ContextFacts.accept(cached, units, ctx)
                if accepted is not None:
                    return accepted, why
        supervisor = Supervisor(
            ParallelScanner.start_context(), setup, f"{__name__}:ContextWork.run",
            ParallelScanner.BOUNDS, 1, deadline=ctx.deadline,
        )  # fmt: skip
        supervisor.template = template
        size = sum(len(unit.content.raw) for unit in units)
        outcome = supervisor.run([Unit(0, item, size)])
        if 0 in outcome.results:
            answer = outcome.results[0]
            if isinstance(answer, str):
                accepted, why = ContextFacts.accept(answer, units, ctx)
                if accepted is not None and digest:
                    ContextCache.put(cache, digest, answer, DOCUMENT_BYTES)
                return accepted, why
            return None, "its worker answered with something that is not a document"
        if 0 in outcome.failed:
            return None, f"its worker ended: {outcome.failed[0]}"
        if outcome.unstarted:
            return None, "the scan's budget was spent before it finished"
        return None, "its worker gave no answer"

    def cache_digest(self, item: tuple[Any, ...], ctx: ScanContext) -> str:
        """Everything the context worker's answer depends on: each unit's path, sha256, language,
        project and where it is opened (never its bytes; the hash stands for them), the target and
        how it is read, the hooks pending from the walk, the context the parent built, and the
        code, intelligence, rule file and Python that read them (`CacheSignature`). One byte of
        one file changed, or a different scanner, and it is another key."""
        import hashlib
        import sys

        from cordon_scanner.engine.cache import CACHE_VERSION, CacheSignature
        from cordon_scanner.engine.canonical import Canonical

        kind, items, read_root, root, where, image, pending_hooks = item
        digest = hashlib.sha256()
        Canonical.feed(
            digest,
            {
                "version": CACHE_VERSION,
                "kind": kind,
                "units": [
                    [path, sha, language, project, opens]
                    for path, sha, _, language, project, opens in items
                ],
                "read_root": read_root,
                "root": root,
                "where": where,
                "image": image,
                "pending_hooks": pending_hooks,
                "code": CacheSignature._package_hash(),
                "context": CacheSignature.context_digest(ctx),
                "intel": CacheSignature._intel_state(),
                "rule_file": CacheSignature._rule_file_digest(self.engine.config),
                "config": self.engine.config.to_dict(),
                "python": sys.version,
            },
        )
        return digest.hexdigest()

    def _failed(
        self, units: list[FileUnit], acc: Accumulator, ctx: ScanContext, where: str, why: str
    ) -> ScanContext:
        """The gap a failed context worker leaves, and the context the walk alone gives."""
        from cordon_scanner.engine.isolation.documents import Documents

        acc.incomplete(
            OperationalFinding.build(
                path=where,
                rule_id=self.RULE,
                message=(
                    "What runs at install, at import and when an agent calls it, and the "
                    f"dependency graph, were not worked out: {why}. Every file was still "
                    "examined, but without knowing which of them run."
                ),
                remediation="Rescan; if it recurs, report it with the package.",
                severity=Severity.HIGH,
            )
        )
        # What the worker would have decoded is not held: every later ask is that file's gap.
        Documents.end()
        Documents.activate(units, failed=True)
        self.archive_graph = None
        return replace(ctx, tree_paths=frozenset(u.path for u in units))

    def _apply(
        self, accepted: Accepted, units: list[FileUnit], acc: Accumulator, ctx: ScanContext
    ) -> ScanContext:
        """The worker's answer as this scan's own: units, findings, coverage, the store, context."""
        from cordon_scanner.detect.base import FileUnit
        from cordon_scanner.engine.isolation.documents import Documents
        from cordon_scanner.engine.pipeline.graph import ParsedManifests
        from cordon_scanner.foundation.content import FileContent

        for index, language in accepted.languages.items():
            units[index] = replace(units[index], language=language)
        limits = self.engine.config.limits
        for path, text, language, project in accepted.added:
            content = FileContent.from_bytes(path, text.encode("utf-8"), limits)
            units.append(FileUnit(content=content, language=language, project=project))
        for finding in accepted.findings:
            acc.append(finding)
        acc.absorb(accepted.complete, tuple(accepted.gaps))
        acc.not_installed.extend(accepted.not_installed)
        for path, why_raised in accepted.raised.items():
            ParsedManifests.absorb_raised(path, why_raised)
        self.engine._sbom_listed[:] = accepted.sbom_listed
        self.archive_graph = accepted.archive_dependencies
        Documents.activate(units)
        if accepted.inventory_hooks is not None and ctx.repository is not None:
            ctx = replace(ctx, repository=replace(ctx.repository, hooks=accepted.inventory_hooks))
        return replace(ctx, **accepted.context)

    def archive_dependencies(self, acc: Accumulator) -> tuple[Dependency, ...]:
        """The archive's graph the context worker built, its findings, coverage and the records
        outside the install set applied to `acc` here, where the parent built it before (item 56
        (b), part 2). None held (the worker failed, or its graph step did): no graph, and the gap
        that failure already left."""
        graph, self.archive_graph = self.archive_graph, None
        if graph is None:
            return ()
        dependencies, findings, complete, gaps, outside = graph
        for finding in findings:
            acc.append(finding)
        acc.absorb(complete, tuple(gaps))
        acc.not_installed.extend(outside)
        return tuple(dependencies)


__all__ = [
    "CONTEXT_FIELDS",
    "Codec",
    "ContextFacts",
    "ContextStage",
    "ContextWork",
]  # Codec: records
