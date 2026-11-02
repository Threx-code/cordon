"""Manifests, JSON documents and JavaScript references decoded in the context worker, served to the
parent's steps after it (item 56, phase (b), part 2): the parent decodes no manifest, no scanned JSON and
no script.

The context worker parses every manifest-shaped unit (`ParsedManifests.manifest_alone`, and
`Graph.manifest_of` with the whole scan in view for an ecosystem that reads its tree), decodes every
JSON-shaped unit (`foundation.formats.served_json`), and reads each JavaScript file's references
(`JsReferences`). The records come back field by field (`Codec`, a closed type table). In the parent:

```
  manifest_of / manifest_alone ──► Documents.manifest(ecosystem, unit, view)  ── the worker's record
  a scanned-JSON site ───────────► ServedJson.loads(data, path) ──────────────── the worker's value
  the intent layer's closure ────► Documents.js_closure(units, seeds) ─────────── a join over paths
  none held ──► DocumentUnavailable, and the path recorded: a blocking gap at the scan's end
```

A miss is never a parse here: it is that file's gap (`report_missing`), so a step the worker did not
anticipate shows up in every identity run instead of quietly parsing in the parent. Outside a scan's
parent (a worker, a test, the CLI's own files) the store is inactive and every call reads as before.
"""

from __future__ import annotations

import contextvars
import dataclasses
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.foundation.formats.served_json import DocumentUnavailable, ServedJson
from cordon_scanner.foundation.models import Severity
from cordon_scanner.foundation.results import OperationalFinding

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from cordon_scanner.detect.base import FileUnit

JSON_SUFFIXES = (".json", ".jsonc", ".json5", ".har", ".webmanifest", ".map", ".lock")
"""Units whose JSON the worker decodes besides every manifest: the shapes the parent's steps read."""


@dataclasses.dataclass(frozen=True, slots=True)
class PendingHooks:
    """Where a manifest's hooks go in the inventory's hook list, held for the context worker
    (`Engine.inventory(defer_manifest_hooks=True)`): the file, its ecosystem, and whether it is read
    with the walked tree in view."""

    real_path: str
    rel_path: str
    ecosystem: str
    in_tree: bool


class _Held:
    """One scan's store, per scan and never per process: two scans in one process (a library user's
    threads, the MCP server, the cloud runner) each read their own (outer-layer review of item 56)."""

    __slots__ = ("manifests", "missing", "references", "state")

    def __init__(self) -> None:
        self.manifests: dict[tuple[str, str, str], Any] = {}
        """(ecosystem id, path, "alone" or "tree") → the Manifest record, or the error text it raised."""
        self.references: dict[str, list[str]] = {}
        """Each JavaScript file's references (`JsReferences.file`), read in the worker."""
        self.missing: dict[str, str] = {}
        """Paths asked for and not held (manifests and references), with what was asked."""
        self.state: dict[str, Any] = {}
        """`view`: the (path, sha256) set the worker parsed in-tree manifests in view of; `failed`: the
        context worker failed, and OPERATIONAL.WORKER.CONTEXT_FAILED already says nothing it would
        have decoded is known, so a later ask is not reported again, file by file."""


class Documents:
    """The parent's store of what the context worker decoded, active for one scan."""

    _current: ClassVar[contextvars.ContextVar[_Held | None]] = contextvars.ContextVar(
        "cordon_documents", default=None
    )

    @staticmethod
    def _scan() -> _Held:
        held = Documents._current.get()
        if held is None:
            held = _Held()
            Documents._current.set(held)
        return held

    @staticmethod
    def accept(manifests: Any, documents: Any, references: Any, known: set[str]) -> str:
        """Why the worker's sections are refused, or "" when each entry has its declared shape and
        the store holds them."""
        from cordon_scanner.ecosystems.base import Manifest
        from cordon_scanner.engine.isolation.records import Codec

        held: dict[tuple[str, str, str], Any] = {}
        for entry in manifests if isinstance(manifests, list) else [None]:
            if not (
                isinstance(entry, list)
                and len(entry) == 5
                and isinstance(entry[0], str)
                and entry[1] in known
                and entry[2] in ("alone", "tree")
                and (entry[4] is None or (isinstance(entry[4], str) and len(entry[4]) <= 128))
            ):
                return "a manifest entry of the wrong shape"
            record = (
                entry[4] or "Exception" if entry[3] is None else Codec.decode(Manifest, entry[3])
            )
            if record is None:
                return "a manifest record of the wrong shape"
            held[(entry[0], entry[1], entry[2])] = record
        why = Documents._accept_references(references, known) or ServedJson.hold(documents, known)
        if why:
            return why
        Documents._scan().manifests.clear()
        Documents._scan().manifests.update(held)
        return ""

    @staticmethod
    def _accept_references(references: Any, known: set[str]) -> str:
        if not isinstance(references, dict) or len(references) > 1_000_000:
            return "JavaScript references of the wrong shape"
        for path, stems in references.items():
            if path not in known or not isinstance(stems, list) or len(stems) > 1_000_000:
                return "JavaScript references of the wrong shape"
            if not all(isinstance(s, str) and len(s) <= 4096 for s in stems):
                return "a JavaScript reference of the wrong shape"
        Documents._scan().references.clear()
        Documents._scan().references.update(references)
        return ""

    @staticmethod
    def activate(units: list[FileUnit], *, failed: bool = False) -> None:
        """The store serves this scan from now on, its in-tree records in view of these units."""
        Documents._scan().missing.clear()
        Documents._scan().state.update(
            view=frozenset((u.path, u.content.sha256) for u in units), failed=failed, active=True
        )
        ServedJson.activate()

    @staticmethod
    def end() -> None:
        Documents._current.set(None)
        ServedJson.end()

    @staticmethod
    def active() -> bool:
        held = Documents._current.get()
        return held is not None and bool(held.state.get("active"))

    @staticmethod
    def manifest(ecosystem: Any, unit: FileUnit, files: Any | None) -> Any:
        """The worker's record of `unit` for `ecosystem`, read alone (`files` None) or in view of
        `files`; the error it raised, raised again; or DocumentUnavailable."""
        ecosystem_id = getattr(ecosystem, "id", "") or ""
        kind = "alone"
        if files is not None and getattr(ecosystem, "parse_in_tree", None) is not None:
            kind = "tree"
            seen = frozenset((path, content.sha256) for path, content in files.items())
            if seen != Documents._scan().state.get("view"):
                return Documents._miss(unit.path, f"{ecosystem_id} manifest, in another view")
        held = Documents._scan().manifests.get((ecosystem_id, unit.path, kind))
        if held is None:
            return Documents._miss(unit.path, f"{ecosystem_id} manifest")
        if isinstance(held, str):
            raise DocumentUnavailable(f"the manifest did not parse in the context worker ({held})")
        return held

    @staticmethod
    def js_closure(
        units: Any, seeds: set[str], closure: Callable[[Any, set[str]], set[str]]
    ) -> set[str]:
        """`closure(units, seeds)` (`Hooks.hook_js_closure`): in a scan's parent, the join over the
        worker's references, never a read of a file; elsewhere, the closure itself."""
        if not Documents.active():
            return closure(units, seeds)
        held: dict[str, list[str]] = {}
        for unit in units:
            if not unit.path.endswith((".js", ".cjs", ".mjs")) or unit.content.is_binary:
                continue
            stems = Documents._scan().references.get(unit.path)
            if stems is None:
                Documents._scan().missing.setdefault(unit.path, "JavaScript references")
            else:
                held[unit.path] = stems
        return Documents.closure_over(held, seeds)

    @staticmethod
    def closure_over(references: Mapping[str, list[str]], hooks: set[str]) -> set[str]:
        """The JavaScript closure from `hooks` over each file's references (`JsReferences`): set
        arithmetic over paths, reading no content, so the parent may run it (item 56 (b))."""
        from cordon_scanner.engine.pipeline.constants import JS_CLOSURE_LIMIT

        pending = sorted(path for path in hooks if path in references)  # a set: fixed order (#23)
        found: set[str] = set()
        while pending and len(found) < JS_CLOSURE_LIMIT:
            current = pending.pop()
            for stem in references[current]:
                for candidate in (
                    stem,
                    f"{stem}.js",
                    f"{stem}.cjs",
                    f"{stem}.mjs",
                    f"{stem}/index.js",
                ):
                    if (
                        candidate in references
                        and candidate not in found
                        and candidate not in hooks
                    ):
                        found.add(candidate)
                        pending.append(candidate)
                        break
        return found

    @staticmethod
    def _miss(path: str, what: str) -> Any:
        Documents._scan().missing.setdefault(path, what)
        raise DocumentUnavailable(f"the context worker returned no {what} for this file")

    @staticmethod
    def report_missing(acc: Any) -> None:
        """Each file a step asked for and the store did not hold: a blocking gap, never a parse."""
        missing = {**ServedJson.missing(), **Documents._scan().missing}
        Documents._scan().missing.clear()
        if Documents._scan().state.get("failed"):
            return
        for path, what in sorted(missing.items()):
            acc.incomplete(
                OperationalFinding.build(
                    path=path,
                    rule_id="OPERATIONAL.WORKER.DOCUMENT_UNAVAILABLE",
                    message=f"A step needed this file's {what}, which the context worker did not "
                    "return, so the step read nothing of it.",
                    remediation="Rescan; if it recurs, report it with the package.",
                    severity=Severity.MEDIUM,
                )
            )


__all__ = ["DocumentUnavailable", "Documents", "PendingHooks"]
