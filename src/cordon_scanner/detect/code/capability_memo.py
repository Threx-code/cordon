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
    """`CapabilityDetector._match_capabilities`, through the memo."""

    MATCHES: ClassVar[ContentMemo] = ContentMemo()

    @staticmethod
    def hits(
        detector: Any, content: FileContent, candidates: tuple[Any, ...], language: str | None
    ) -> list[Any]:
        def work() -> list[Any]:
            found: list[Any] = detector._match_capabilities(content, candidates, language)
            return found

        if content.window_of is not None or content.truncated or content.streamed is not None:
            return work()
        return CapabilityMemo.MATCHES.get(
            ("capabilities", language, Same(candidates)), content.raw, work
        )


__all__ = ["CapabilityMemo"]
