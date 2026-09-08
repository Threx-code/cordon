"""Plugin discovery and registration.

Detectors, reporters, sources and ecosystems are all discovered through Python
entry points, and the built-in components use exactly the same mechanism a third
party would. There is no privileged path: if the plugin system is broken for
external authors, it is broken for us first, and we find out immediately rather
than at the first bug report.

Third-party plugins are **disabled by default**. A scanner that silently loads
executable code from whatever happens to be installed in its environment has the
same shape as the attacks it exists to detect, so enabling them requires an
explicit flag or an organisation-policy allowlist. Plugins are never loaded from
the repository being scanned.
"""

from __future__ import annotations

from importlib.metadata import entry_points
from typing import TYPE_CHECKING, Any

from cordon.core.errors import CordonError

if TYPE_CHECKING:
    from collections.abc import Sequence

DETECTOR_GROUP = "cordon.detectors"
REPORTER_GROUP = "cordon.reporters"
SOURCE_GROUP = "cordon.sources"
ECOSYSTEM_GROUP = "cordon.ecosystems"

# Components shipped with Cordon. Named explicitly so that a third-party package
# cannot shadow a built-in by registering the same entry-point name: an attacker
# who can install a package into the scanning environment should not be able to
# silently replace the malware detector.
BUILTIN_DETECTORS = ("capability",)
BUILTIN_REPORTERS = ("text", "json", "sarif", "junit", "markdown", "github")


class Registry:
    """Discovers and instantiates plugins for one Scanner."""

    def __init__(self, *, allow_third_party: bool = False) -> None:
        self.allow_third_party = allow_third_party

    def detectors(self, *, only: Sequence[str] | None = None) -> tuple[Any, ...]:
        return self._load(DETECTOR_GROUP, BUILTIN_DETECTORS, only)

    def reporters(self, *, only: Sequence[str] | None = None) -> tuple[Any, ...]:
        return self._load(REPORTER_GROUP, BUILTIN_REPORTERS, only)

    def reporter(self, name: str) -> Any:
        found = self._load(REPORTER_GROUP, BUILTIN_REPORTERS, [name])
        if not found:
            available = ", ".join(BUILTIN_REPORTERS)
            raise CordonError(
                f"unknown output format {name!r}",
                hint=f"Available formats: {available}",
            )
        return found[0]

    def _load(
        self, group: str, builtin: Sequence[str], only: Sequence[str] | None
    ) -> tuple[Any, ...]:
        selected: list[Any] = []
        wanted = set(only) if only is not None else None

        # Sorted so that load order, and anything that depends on it, is
        # reproducible across machines and Python versions.
        for entry in sorted(entry_points(group=group), key=lambda e: e.name):
            if entry.name not in builtin and not self.allow_third_party:
                continue
            if wanted is not None and entry.name not in wanted:
                continue
            try:
                selected.append(entry.load()())
            except Exception as exc:
                raise CordonError(
                    f"failed to load {group} plugin {entry.name!r}: "
                    f"{type(exc).__name__}: {exc}",
                    hint="Reinstall the package providing it, or disable the plugin.",
                ) from exc

        return tuple(selected)


def default_detectors() -> tuple[Any, ...]:
    """Built-in detectors, for callers that have not built a Registry."""
    return Registry().detectors()


__all__ = [
    "BUILTIN_DETECTORS",
    "BUILTIN_REPORTERS",
    "DETECTOR_GROUP",
    "ECOSYSTEM_GROUP",
    "REPORTER_GROUP",
    "SOURCE_GROUP",
    "Registry",
    "default_detectors",
]
