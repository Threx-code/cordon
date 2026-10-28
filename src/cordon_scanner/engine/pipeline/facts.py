"""Facts about the scanned tree that the detectors are handed with each file: which files are a
package's entry points, which a skill runs, which native code ships, where its provenance is
declared, and which files were already labelled once.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from cordon_scanner.detect.base import (
    FileUnit,
    ScanContext,
)
from cordon_scanner.foundation.errors import SourceError

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence


class TreeFacts:
    """Facts about the scanned tree, gathered once for every detector."""

    @staticmethod
    def provenance(root: Path) -> tuple[bool, str | None, str | None, bool]:
        """The commit and remote this scan describes.

        `Repository` declared both fields, `to_dict` serialised both, and
        nothing ever set either -- so every report and every SARIF upload
        recorded `null` for the two values that say *which* code was examined.
        A result nobody can tie to a commit is a result nobody can act on later:
        it says a repository was clean without saying which version of it.

        `GitRepository.discover` already computed both, including stripping any
        credential from the remote, and its answer was simply never asked for.

        `is_git` had the identical defect and is returned here for the same
        reason. It gated whether any repository-scoped detector runs at all, so
        leaving it false meant the history checks were shipped and never
        executed -- a detector that cannot run is indistinguishable from one
        that found nothing.

        Failure is silent on purpose. A directory that is not a repository is
        the ordinary case, not a degraded scan, and it is already visible in the
        report as an absent revision.
        """
        from cordon_scanner.sources.registry import GitRepository

        try:
            info = GitRepository.discover(root)
        except (SourceError, OSError):  # pragma: no cover - defensive
            return (False, None, None, False)
        if info is None:
            return (False, None, None, False)
        # Whether the target is the repository root, which is a different question
        # from whether a repository is above it. Resolved on both sides, so a
        # symlinked or relative target does not read as a subdirectory of itself.
        try:
            at_root = Path(info.root).resolve() == Path(root).resolve()
        except OSError:  # pragma: no cover - defensive
            at_root = False
        return (True, info.revision, info.remote, at_root)

    @staticmethod
    def shipped_native(units: Iterable[FileUnit]) -> frozenset[str]:
        """Paths whose bytes begin with ELF, PE or Mach-O magic: a binary the package ships (census A)."""
        from cordon_scanner.detect.registry import NATIVE_FORMATS, BinaryDetector

        ids = ((u.path, BinaryDetector.identify(u.content.raw)) for u in units if u.content)
        return frozenset(p for p, f in ids if f is not None and f.name in NATIVE_FORMATS)

    @staticmethod
    def entry_points_reached(
        deferred: frozenset[tuple[str, int, int]], agent_run: set[str]
    ) -> frozenset[tuple[str, int, int]]:
        """Deferred bodies, less those in code an agent runs: a skill script's functions and an MCP
        server's handlers are called by the agent by name, so none of them is unreached. Counted as
        deferred, a skill script appending to `/etc/passwd` and `/etc/crontab` from its functions
        had no install-time finding at all (review 98)."""
        return frozenset(t for t in deferred if t[0] not in agent_run)

    @staticmethod
    def skill_scripts(units: Sequence[FileUnit]) -> set[str]:
        """Scripts an agent skill ships (`LoadPath.skill_script`)."""
        from types import SimpleNamespace

        from cordon_scanner.detect.registry import LoadPath

        tree = SimpleNamespace(tree_paths=frozenset(u.path for u in units))
        return {
            u.path
            for u in units
            if LoadPath.skill_script(u.path, tree)  # type: ignore[arg-type]
        }

    @staticmethod
    def labelled_once(
        detector: Any, unit: FileUnit, ctx: ScanContext, cache: dict[str, Any] | None
    ) -> Any:
        """`detector.labelled(unit, ctx)`, computed once per file for everything that asks."""
        if cache is None:
            return detector.labelled(unit, ctx)
        if unit.path not in cache:
            try:
                cache[unit.path] = detector.labelled(unit, ctx)
            except Exception as error:  # re-raised to each caller below  # noqa: BLE001
                cache[unit.path] = error
        held = cache[unit.path]
        if isinstance(held, Exception):
            raise held
        return held


__all__ = ["TreeFacts"]
