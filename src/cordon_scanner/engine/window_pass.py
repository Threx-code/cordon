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

import gc
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from cordon_scanner.analysis.python.statements import PythonStatements
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
            WindowPass._read(unit, source, windows, picked, inspect, seen, out)
            cut = STATEMENT_CUTS.get(unit.language or "")
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
    ) -> None:
        """Each detector over each window, its findings placed in the whole file, new ones kept.

        With `release`, the registered caches are emptied after each window: a statement window is
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
                for finding in inspect(detector, part):
                    moved = (
                        WindowPass.shifted(finding, window.lines_before, window.begin)
                        if finding.location.path == content.path
                        else finding
                    )
                    key = (moved.rule_id, moved.location.line)
                    if key not in seen:
                        seen.add(key)
                        out.append(moved)
            if release:
                del part
                ScanCaches.after_scan()
                # A window's tree is freed by the cycle collector, not by reference counts (a tree
                # parsed outside the shared cache keeps its own walk list, which holds the tree):
                # left to the collector's thresholds, datadog's trees piled up, about 800 MB a
                # window, to 5.7 GB. Collected here, once per window, they are gone before the next.
                gc.collect()

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


__all__ = ["WINDOW_DETECTORS", "WindowPass"]
