"""The capability detector's pattern-tier hits, worked out once per distinct whole file.

A package can carry the same file many times -- vendored copies, a bundle under several names --
and the pattern tier's hits depend on a file's bytes, the rules selected for it and its language
alone. They are kept by `analysis.shared.content_memo`, keyed by the bytes' digest, the language
and the selected rules themselves (by identity, held while the entry is kept). A window of a
larger file, or a file cut short, is matched every time: its line numbers are its own.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.analysis.shared.content_memo import ContentMemo, Same

if TYPE_CHECKING:
    from cordon_scanner.foundation.content import FileContent


class CapabilityMemo:
    """`Labelling.match_capabilities`, through the memo."""

    MATCHES: ClassVar[ContentMemo] = ContentMemo()

    @staticmethod
    def hits(
        labelling: Any, content: FileContent, candidates: tuple[Any, ...], language: str | None
    ) -> list[Any]:
        def work() -> list[Any]:
            found: list[Any] = labelling.match_capabilities(content, candidates, language)
            return found

        if content.window_of is not None or content.truncated or content.streamed is not None:
            return work()
        return CapabilityMemo.MATCHES.get(
            ("capabilities", language, Same(candidates)), content.raw, work
        )


__all__ = ["CapabilityMemo"]


class LabelledNames:
    """The capability names the detector's own pass found in the file a worker is inspecting, kept for that worker's
    facts (`engine/isolation/analysis_facts.py`, fact `cap.all`) so every file's names reach the package-scope rules
    and the facts export without labelling the file a second time.

    One entry: a worker inspects one file at a time, and the windows of an oversized file are joined (each window's
    names are added to the file's). `take` empties it, so a name never carries over to the next file."""

    _last: ClassVar[tuple[str, frozenset[str]] | None] = None

    @staticmethod
    def remember(path: str, names: frozenset[str]) -> None:
        last = LabelledNames._last
        if last is not None and last[0] == path:
            names = last[1] | names
        LabelledNames._last = (path, names)

    @staticmethod
    def take(path: str) -> frozenset[str]:
        last, LabelledNames._last = LabelledNames._last, None
        return last[1] if last is not None and last[0] == path else frozenset()
