"""Detectors reading the rest of a large file, a window at a time.

`foundation/files/windows.py` cuts what lies past a file's first `max_file_bytes` into overlapping
windows; this runs every detector that judges text (`WINDOW_DETECTORS`) over each window as it
would over a small file, moves each finding to its place in the whole file, and drops the repeats
the overlaps produce. Detectors that judge a file as a whole -- its format, its structure, its
manifest -- do not read windows: a window of a lockfile is not a lockfile.
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Any

from cordon_scanner.detect.base import FileUnit
from cordon_scanner.foundation.content import FileContent
from cordon_scanner.foundation.files.windows import OVERLAP, Windows, WindowSourceChanged

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable

    from cordon_scanner.foundation.models import Finding

WINDOW_DETECTORS = frozenset({"capability", "secrets", "obfuscation", "agents", "rule-file"})
"""Detectors that judge the text in front of them, and so read a window as they read a file."""


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
            for window in Windows.iterate(
                source,
                content.raw,
                size=content.limits.max_file_bytes,
                overlap=OVERLAP,
                limit=content.limits.max_stream_bytes,
            ):
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
                for detector in picked:
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
        except WindowSourceChanged:
            return out, False
        return out, True

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
