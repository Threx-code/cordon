"""Detectors reading the rest of a large file, a window at a time.

`foundation/files/windows.py` cuts what lies past a file's first `max_file_bytes` into overlapping
windows; this runs every detector that judges text (`WINDOW_DETECTORS`) over each window as it
would over a small file, moves each finding to its place in the whole file, and drops the repeats
the overlaps produce. Detectors that judge a file as a whole -- its format, its structure, its
manifest -- do not read windows: a window of a lockfile is not a lockfile.

A language whose syntax tree is read (`STATEMENT_CUTS`) gets a second pass: the whole file from
its first byte in windows cut between top-level statements, so each window parses and the
syntax-tree tier reads the file (review 98, D1: none of a 45 MB generated module's prefix parsed).
Only the detectors with a tree tier (`STRUCTURAL_DETECTORS`) read it, and only for what the first
pass did not find, so every finding already made stands as it was.
"""

from __future__ import annotations

import contextlib
import gc
from dataclasses import replace
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.analysis.python.pysyntax import PythonSyntax
from cordon_scanner.analysis.python.statements import PythonStatements
from cordon_scanner.analysis.python.unparsed_source import Decision, UnparsedSource
from cordon_scanner.detect.base import FileUnit
from cordon_scanner.foundation.collector import ScanCaches
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.files.windows import OVERLAP, Windows, WindowSourceChanged

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from cordon_scanner.foundation.models import Finding

WINDOW_DETECTORS = frozenset({"capability", "secrets", "obfuscation", "agents", "rule-file"})
"""Detectors that judge the text in front of them, and so read a window as they read a file."""

STATEMENT_CUTS: dict[str, Callable[[bytes], int]] = {"python": PythonStatements.last_cut}
"""Where a language's window may end so that it parses: after its last whole top-level statement."""

STRUCTURAL_DETECTORS = frozenset({"capability", "secrets"})
"""Window detectors with a syntax-tree tier: the ones a statement-aligned window adds to."""


class WindowPass:
    #: Whether a windowed piece's text may parse (`PythonStatements.may_parse`), worked out once
    #: for the structural detectors that both ask: its identity -> (the text, the answer).
    _PARSES: ClassVar[dict[int, tuple[str, bool]]] = {}

    @staticmethod
    def withheld(detector_id: str, unit: Any) -> contextlib.AbstractContextManager[None]:
        """What a detector reads `unit` under in the first pass: for a structural detector over the
        prefix of a Python file past `max_file_bytes` that cannot parse (cut inside a statement), its
        text is not parsed (`PythonSyntax.withholding`). The statement-aligned pass parses the same
        bytes as whole statements from byte 0, for the same detectors, and the findings of both are
        one set. Every other detector, and a prefix that may parse, read as before."""
        content = getattr(unit, "content", None)
        if (
            detector_id not in STRUCTURAL_DETECTORS
            or content is None
            or getattr(unit, "language", None) not in STATEMENT_CUTS
            or not content.truncated
            or content.window_source is None
        ):
            return contextlib.nullcontext()
        return WindowPass._unless_it_parses(content.text)

    @staticmethod
    def _forget(text: str) -> None:
        """Drop `text`'s answer from `_PARSES` once nothing reads it again (a plain window)."""
        key = ScanCaches.identity(text)
        kept = WindowPass._PARSES.get(key)
        if kept is not None and kept[0] is text:
            del WindowPass._PARSES[key]

    @staticmethod
    def _unless_it_parses(text: str) -> contextlib.AbstractContextManager[None]:
        key = ScanCaches.identity(text)
        kept = WindowPass._PARSES.get(key)
        if kept is None or kept[0] is not text:
            kept = WindowPass._PARSES[key] = (text, PythonStatements.may_parse(text))
        return contextlib.nullcontext() if kept[1] else PythonSyntax.withholding(text)

    @staticmethod
    def run(
        unit: Any,
        detectors: Iterable[Any],
        inspect: Callable[[Any, Any], Iterable[Finding]],
        already: Iterable[Finding],
    ) -> tuple[list[Finding], bool]:
        """What the window-reading detectors find past the prefix of `unit`'s file, placed in the
        whole file and without what `already` holds. False as the second value when the file could
        not be read again as the same file: the caller reports it, as an unreadable file is."""
        content = unit.content
        source = content.window_source
        if source is None:
            return [], True
        picked = [d for d in detectors if getattr(d, "id", "") in WINDOW_DETECTORS]
        if not picked:
            return [], True
        seen = {(f.rule_id, f.location.line) for f in already}
        out: list[Finding] = []
        try:
            windows = Windows.iterate(
                source,
                content.raw,
                size=content.limits.max_file_bytes,
                overlap=OVERLAP,
                limit=content.limits.max_stream_bytes,
            )
            cut = STATEMENT_CUTS.get(unit.language or "")
            # A plain window of such a file is cut inside a statement as its prefix is: not parsed
            # by the structural detectors either, unless it may parse.
            WindowPass._read(
                unit, source, windows, picked, inspect, seen, out, withhold=cut is not None
            )
            structural = [d for d in picked if getattr(d, "id", "") in STRUCTURAL_DETECTORS]
            if cut is not None and structural:
                # The first pass's caches go before the first statement window too: it would
                # otherwise be parsed on top of them (583 MB held, an 857 MB peak at 3 MiB windows).
                ScanCaches.after_scan()
                gc.collect()
                aligned = Windows.aligned(
                    source,
                    size=content.limits.max_file_bytes,
                    limit=content.limits.max_stream_bytes,
                    cut=cut,
                )
                WindowPass._read(
                    unit, source, aligned, structural, inspect, seen, out, release=True
                )
        except WindowSourceChanged:
            return out, False
        return out, True

    @staticmethod
    def _read(
        unit: Any,
        source: Any,
        windows: Iterable[Any],
        detectors: list[Any],
        inspect: Callable[[Any, Any], Iterable[Finding]],
        seen: set[tuple[str, int | None]],
        out: list[Finding],
        *,
        release: bool = False,
        withhold: bool = False,
    ) -> None:
        """Each detector over each window, its findings placed in the whole file, new ones kept.

        With `withhold`, a structural detector does not parse a window that cannot parse
        (`_unless_it_parses`): a plain window of a statement-cut language. With `release`, the registered caches are emptied after each window: a statement window is
        up to `max_file_bytes` of Python, and its tree is several hundred megabytes, which the
        shared-tree and index caches (4 and 8 deep) would otherwise keep for the windows after it.
        Five of them took datadog 16.0.0 past 4.6 GB (review 98, D1). Files under the limit, and
        the first pass, keep their caches as before."""
        content = unit.content
        for window in windows:
            part = FileUnit(
                content=FileContent(
                    path=content.path,
                    raw=window.data,
                    size=len(window.data),
                    limits=content.limits,
                    window_of=(source, window.begin),
                ),
                language=unit.language,
                project=unit.project,
            )
            for detector in detectors:
                held = (
                    WindowPass._unless_it_parses(part.content.text)
                    if withhold and getattr(detector, "id", "") in STRUCTURAL_DETECTORS
                    else contextlib.nullcontext()
                )
                with held:
                    found = list(inspect(detector, part))
                for finding in found:
                    moved = (
                        WindowPass.shifted(finding, window.lines_before, window.begin)
                        if finding.location.path == content.path
                        else finding
                    )
                    key = (moved.rule_id, moved.location.line)
                    if key not in seen:
                        seen.add(key)
                        out.append(moved)
            if withhold:
                # the answer is needed only while this window is read: kept, it would hold the
                # window's text (up to max_file_bytes) until the scan ends, every window's at once
                WindowPass._forget(part.content.text)
            if release:
                del part
                ScanCaches.after_scan()
                # A window's tree is freed by the cycle collector, not by reference counts (a tree
                # parsed outside the shared cache keeps its own walk list, which holds the tree):
                # left to the collector's thresholds, datadog's trees piled up, about 800 MB a
                # window, to 5.7 GB. Collected here, once per window, they are gone before the next.
                gc.collect()

    @staticmethod
    def unparsed_decision(unit: Any) -> Decision | None:
        """What `UnparsedSource` decides about a Python file read in windows, from its statement-aligned
        windows rather than its prefix (which is cut inside a statement and does not parse): `parses`
        when every window parses and the windows cover the file, else the first window that does not
        (a reading of it counts as a gap: its text is a window, not the file). A file that does not parse
        and carries an act token in ANY window stays a gap, as the file as a whole would (cordon-47). None
        when `unit` is not a windowed Python file, or the file could not be read again as the same file."""
        content = unit.content
        source = content.window_source
        if not content.truncated or source is None or getattr(unit, "language", None) != "python":
            return None
        covered, failed, act = 0, None, False
        try:
            for window in Windows.aligned(
                source,
                size=content.limits.max_file_bytes,
                limit=content.limits.max_stream_bytes,
                cut=PythonStatements.last_cut,
            ):
                text = window.data.decode("utf-8", "replace")
                act = act or UnparsedSource.ACT.search(text) is not None
                # the first window that does not parse decides; the rest are read for acts
                if failed is None:
                    decision = UnparsedSource.decide(text)
                    ScanCaches.after_scan()
                    gc.collect()
                    if decision.kind != "parses":
                        failed = decision
                covered = window.begin + len(window.data)
        except WindowSourceChanged:
            return None
        if failed is None:
            return Decision("parses") if covered >= source.size else None
        gap = failed.kind == "reading" or (failed.kind == "broken" and act)
        return Decision("gap") if gap else failed

    @staticmethod
    def shifted(finding: Finding, lines: int, offset: int) -> Finding:
        """A finding from a window, placed in the whole file."""
        at = finding.location

        def plus(value: int | None, by: int) -> int | None:
            return None if value is None else value + by

        return replace(
            finding,
            location=replace(
                at,
                line=plus(at.line, lines),
                end_line=plus(at.end_line, lines),
                byte_start=plus(at.byte_start, offset),
                byte_end=plus(at.byte_end, offset),
            ),
        )


ScanCaches.register(WindowPass._PARSES)

__all__ = ["WINDOW_DETECTORS", "WindowPass"]
