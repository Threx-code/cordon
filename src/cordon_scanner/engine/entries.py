"""Which files of a published package run when it is used rather than installed.

Moved out of `engine/engine.py` (0.7.0 layout: a long module only shrinks). The engine records
them as `import_entry_paths`, and, without the command targets, as `library_entry_paths`.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.ecosystems.registry import RegistryFacts
from cordon_scanner.foundation.formats.served_json import ServedJson

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

    PROJECT_SCRIPTS: ClassVar[frozenset[str]] = frozenset(
        f"{when}{name}" for name in ("dev", "build", "start") for when in ("", "pre", "post")
    )
    """The scripts a person runs to use a published project (`npm run dev`, `npm start`), with
    the pre and post scripts npm runs around them. Item 72: 323 of 374 npm malware misses with
    code outside every reach set were app projects whose payload runs on these, not on install;
    the owner's ruling is a strict scanner (3 Nov), so what they run is reached code."""

    TOOL_CONFIG: ClassVar[re.Pattern[str]] = re.compile(r"^[\w.-]+\.config\.[cm]?[jt]s$")
    """A build tool's configuration beside the manifest (`next.config.mjs`, `vite.config.ts`):
    code the tool loads and runs when one of those scripts does. A file-name convention, not a
    list of tools."""

    @staticmethod
    def project_run(units: list[FileUnit], distribution: str) -> frozenset[str]:
        """The files a published package's own dev, build and start scripts run, and the tool
        configurations they load: empty for a package with none of those scripts."""
        from cordon_scanner.engine.pipeline.hooks import Hooks
        from cordon_scanner.foundation.models import Hook

        place = RegistryFacts.archive_manifest(distribution)
        scripts = PackageEntries.manifest(units, distribution).get("scripts")
        if place is None or not isinstance(scripts, dict):
            return frozenset()
        hooks = [
            Hook(kind="build", path=place, name=name, command=command)
            for name, command in scripts.items()
            if name in PackageEntries.PROJECT_SCRIPTS and isinstance(command, str)
        ]
        manifest = next((u.path for u in units if u.path.endswith(f"!{place}")), None)
        if not hooks or manifest is None:
            return frozenset()
        known = frozenset(u.path for u in units)
        found = Hooks.hook_script_paths(manifest, hooks, known)
        here = manifest.rpartition("/")[0]
        found.update(
            u.path
            for u in units
            if u.path.rpartition("/")[0] == here
            and PackageEntries.TOOL_CONFIG.match(u.path.rpartition("/")[2])
        )
        return frozenset(found)

    @staticmethod
    def manifest(units: list[FileUnit], distribution: str) -> dict[str, Any]:
        """The published archive's own manifest where its ecosystem fixes the place
        (`archive_manifest`), as a JSON object; {} where there is none or it does not read."""
        place = RegistryFacts.archive_manifest(distribution)
        if place is None:
            return {}
        manifest = next((u for u in units if u.path.endswith(f"!{place}")), None)
        try:
            document = (
                ServedJson.loads(manifest.content.text, manifest.path)
                if manifest is not None
                else {}
            )
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
