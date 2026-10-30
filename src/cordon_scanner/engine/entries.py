"""Which files of a published package run when it is used rather than installed.

Moved out of `engine/engine.py` (0.7.0 layout: a long module only shrinks). The engine records
them as `import_entry_paths`, and, without the command targets, as `library_entry_paths`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cordon_scanner.ecosystems.registry import RegistryFacts
from cordon_scanner.foundation.formats.scanned_json import ScannedJson

if TYPE_CHECKING:
    from cordon_scanner.detect.base import FileUnit


class PackageEntries:
    @staticmethod
    def of(units: list[FileUnit], distribution: str, *, with_bin: bool = True) -> frozenset[str]:
        """The files of a published package that run when it is used rather than installed: npm's
        `main` (or `index.js`), `bin` and `exports` targets; a wheel's or sdist's top-level
        `__init__.py`. Their module top level runs on `require()`, `import` or the command, on
        every consumer, with no hook in the manifest (review 98, REC-2)."""
        members: dict[str, str] = {}
        for unit in units:
            _, sep, member = unit.path.partition("!")
            if sep and "!" not in member:
                members[member] = unit.path
        manifest = PackageEntries.manifest(units, distribution)
        return frozenset(RegistryFacts.library_entries(distribution, members, manifest, with_bin))

    @staticmethod
    def manifest(units: list[FileUnit], distribution: str) -> dict[str, Any]:
        """The published archive's own manifest where its ecosystem fixes the place
        (`archive_manifest`), as a JSON object; {} where there is none or it does not read."""
        place = RegistryFacts.archive_manifest(distribution)
        if place is None:
            return {}
        manifest = next((u for u in units if u.path.endswith(f"!{place}")), None)
        try:
            document = ScannedJson.loads(manifest.content.text) if manifest is not None else {}
        except (ValueError, RecursionError):
            return {}
        return document if isinstance(document, dict) else {}

    @staticmethod
    def repository(units: list[FileUnit], distribution: str) -> str:
        """The published package's own `repository` URL, or "": a string, or an object's `url`, as
        its manifest declares it (review 98, FP-2)."""
        return RegistryFacts.published_repository(
            distribution, PackageEntries.manifest(units, distribution)
        )


__all__ = ["PackageEntries"]
