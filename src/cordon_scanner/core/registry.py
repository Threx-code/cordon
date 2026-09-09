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

import importlib.util
from importlib.metadata import entry_points
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cordon_scanner.core.errors import ConfigError, CordonError

if TYPE_CHECKING:
    from collections.abc import Sequence

DISTRIBUTION = "cordon-scanner"
"""The distribution whose entry points are trusted without `allow_plugins`.

Trust has to follow the distribution rather than the entry-point name, because
the name is the part an attacker controls: registering `cordon.detectors:
capability = evil:Boom` is free, and a name allowlist waves it straight through.
"""

_PACKAGE_ROOT = Path(__file__).resolve().parent.parent
"""This package's own directory on disk.

The anchor for plugin trust. A built-in detector is a module inside it; nothing
installed from elsewhere can be, whatever its metadata claims."""

DETECTOR_GROUP = "cordon_scanner.detectors"
REPORTER_GROUP = "cordon_scanner.reporters"
SOURCE_GROUP = "cordon_scanner.sources"
ECOSYSTEM_GROUP = "cordon_scanner.ecosystems"

# Components shipped with Cordon. Named explicitly so that a third-party package
# cannot shadow a built-in by registering the same entry-point name: an attacker
# who can install a package into the scanning environment should not be able to
# silently replace the malware detector.
BUILTIN_DETECTORS = (
    "advisory",
    "capability",
    "config",
    "dependency",
    "lockfile",
    "manifest",
    "obfuscation",
    "secrets",
)
BUILTIN_REPORTERS = ("text", "json", "sarif", "junit", "markdown", "github")


class Registry:
    """Discovers and instantiates plugins for one Scanner."""

    @classmethod
    def default_detectors(cls) -> tuple[Any, ...]:
        """Built-in detectors, for callers that have not built a Registry."""
        return cls().detectors()

    def __init__(self, *, allow_third_party: bool = False) -> None:
        self.allow_third_party = allow_third_party

    def detectors(self, *, only: Sequence[str] | None = None) -> tuple[Any, ...]:
        """Load detectors, refusing an unrecognised name.

        A typo in `--detector` previously selected nothing, ran no checks, found
        nothing and exited zero. That is the worst possible outcome: a mistyped
        flag in a CI file silently disables all scanning while the pipeline stays
        green. An unknown name is now a configuration error.
        """
        loaded = self._load(DETECTOR_GROUP, BUILTIN_DETECTORS, only)

        if only is not None:
            found = {getattr(d, "id", "") for d in loaded}
            unknown = sorted(set(only) - found)
            if unknown:
                available = ", ".join(sorted(BUILTIN_DETECTORS))
                raise ConfigError(
                    f"unknown detector(s): {', '.join(unknown)}",
                    hint=f"Available detectors: {available}",
                )

        return loaded

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
        seen: dict[str, str] = {}

        # Sorted so that load order, and anything that depends on it, is
        # reproducible across machines and Python versions.
        for entry in sorted(entry_points(group=group), key=lambda e: e.name):
            provider = self._provider(entry)
            builtin_name = entry.name in builtin
            # Trust follows where the code *is*, not what its metadata says it
            # is. See `_is_ours`.
            ours = self._is_ours(entry, provider)

            # Trust follows the *distribution*, not the entry-point name.
            #
            # This test used to be `entry.name not in builtin`, which is the
            # exact inverse of what the surrounding comment claimed. Because
            # `entry_points()` enumerates every installed distribution, a
            # malicious package registering `cordon.detectors: capability =
            # evil:Boom` satisfied `entry.name in builtin`, skipped the guard
            # entirely, and had `entry.load()()` called on it with plugins
            # disabled -- arbitrary code execution inside the scanner, before
            # any scanning. The name allowlist is the one thing an attacker
            # copies.
            if not ours:
                if builtin_name:
                    raise ConfigError(
                        f"{group} plugin {entry.name!r} is provided by {provider!r} but "
                        f"shadows a built-in of the same name",
                        hint=(
                            "A package that replaces a built-in detector can silently "
                            "disable it. Uninstall the package, or report it if you did "
                            "not install it deliberately."
                        ),
                    )
                if not self.allow_third_party:
                    continue

            if wanted is not None and entry.name not in wanted:
                continue

            if entry.name in seen:
                raise ConfigError(
                    f"{group} plugin {entry.name!r} is provided twice, by "
                    f"{seen[entry.name]!r} and {provider!r}",
                    hint=(
                        "Two providers of the same id means which one runs depends on "
                        "import order. Uninstall one."
                    ),
                )
            seen[entry.name] = provider

            try:
                selected.append(entry.load()())
            except Exception as exc:
                raise CordonError(
                    f"failed to load {group} plugin {entry.name!r}: {type(exc).__name__}: {exc}",
                    hint="Reinstall the package providing it, or disable the plugin.",
                ) from exc

        return tuple(selected)

    @classmethod
    def _is_ours(cls, entry: Any, provider: str) -> bool:
        """Whether this entry point is genuinely part of this package.

        The distribution name is not evidence. It is the plaintext `Name:` field
        of a `.dist-info/METADATA` file, and anything on `sys.path` can declare
        `Name: cordon-scanner`. An audit demonstrated the consequence: a stub
        package on `PYTHONPATH` was trusted as Cordon itself and had
        `entry.load()()` called on it with plugins disabled -- arbitrary code
        execution inside the scanner, before any scanning, in the process that
        on a CI runner holds the publish tokens this tool exists to protect.

        The comment above `DISTRIBUTION` had the right instinct and the wrong
        conclusion: it identified the entry-point *name* as attacker-controlled
        and moved trust to the distribution name, which is attacker-controlled
        in exactly the same way and for the same reason.

        Location is not. A built-in lives inside this package's own directory;
        nothing an attacker installs elsewhere does. The module is resolved
        without importing it, so a package that merely claims to be us is
        rejected before any of its code runs -- checking after `load()` would be
        checking after the payload had already executed.
        """
        if provider != DISTRIBUTION:
            return False
        module_name = str(getattr(entry, "module", "") or entry.value.partition(":")[0])
        if not module_name:
            return False
        try:
            spec = importlib.util.find_spec(module_name)
        except (ImportError, ValueError, AttributeError):
            return False
        origin = getattr(spec, "origin", None) if spec is not None else None
        if not origin:
            return False
        try:
            return Path(origin).resolve().is_relative_to(_PACKAGE_ROOT)
        except (OSError, ValueError):  # pragma: no cover - unresolvable path
            return False

    @staticmethod
    def _provider(entry: Any) -> str:
        """Which distribution registered this entry point.

        Returns a sentinel rather than None when the metadata is unavailable, so
        an entry whose origin cannot be established is never mistaken for one
        that belongs to this package.
        """
        try:
            dist = entry.dist
        except Exception:  # pragma: no cover - importlib.metadata internals
            return "<unknown>"
        name = getattr(dist, "name", None) if dist is not None else None
        return name or "<unknown>"


__all__ = [
    "BUILTIN_DETECTORS",
    "BUILTIN_REPORTERS",
    "DETECTOR_GROUP",
    "DISTRIBUTION",
    "ECOSYSTEM_GROUP",
    "REPORTER_GROUP",
    "SOURCE_GROUP",
    "Registry",
]
