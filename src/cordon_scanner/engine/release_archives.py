"""How `ReleaseHistory.acquire` reads an established release's archive (`intel.base.ReleaseArchiveReader`):
with the scanner's own archive reader and the packing signatures `SUSPECT.OBFUSCATION.PACKED.001`
reports. Both live above intel, so its caller hands this in (architecture audit F1)."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable


class ReleaseArchives:
    """The scanner's way of reading a published archive."""

    @staticmethod
    def members(data: bytes, filename: str) -> Iterable[tuple[str, bytes]]:
        from cordon_scanner.sources.registry import ArchiveReader

        return ArchiveReader.walk_archive(data, path=filename)

    @staticmethod
    def packed(path: str, data: bytes) -> bool:
        """Whether a text file has an obfuscator's output shape. Matched, never decoded."""
        from cordon_scanner.analysis.shared.languages import LanguageRegistry
        from cordon_scanner.detect.registry import PackingFindings
        from cordon_scanner.foundation.content import FileContent

        content = FileContent.from_bytes(path, data)
        if content.is_binary:
            return False
        language = LanguageRegistry.of_file(path, content)
        return any(True for _ in PackingFindings.packers(content, language))


__all__ = ["ReleaseArchives"]
