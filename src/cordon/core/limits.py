"""Resource governance.

Cordon is pointed, by design, at code that may be actively hostile, on machines
that hold production credentials. From the scanner's perspective a decompression
bomb, a symlink pointing at a private key, a one-gigabyte single-line file and a
pattern crafted to trigger catastrophic backtracking are all ordinary inputs.

Every limit here maps to a specific attack in ``docs/02-THREAT-MODEL.md``, and
each is enforced at the point it protects rather than validated once at startup.
A limit checked before the work begins does not help when the work is what
consumes the resource.

One rule governs the whole module:

    Reaching a limit produces an ``OPERATIONAL`` finding. It is never a silent
    skip.

A scanner that quietly stops examining things is indistinguishable from one whose
limits do not work, and both report success. Coverage that silently shrinks is
the most dangerous failure a security tool can have, because the output looks
exactly like a clean result.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

_LIMIT_RANGES: dict[str, tuple[float, float | None, type]] = {
    # name: (minimum, maximum or None, accepted type)
    "max_file_bytes": (1, None, int),
    "max_line_bytes": (1, None, int),
    "max_total_bytes": (1, None, int),
    "max_files": (1, None, int),
    "max_findings": (0, None, int),
    "max_dependencies": (1, None, int),
    "per_file_timeout": (0, 86400, float),
    "total_timeout": (0, 604800, float),
    "max_archive_ratio": (1, None, int),
    "max_archive_entries": (1, None, int),
    "max_archive_depth": (0, 32, int),
    "max_uncompressed_bytes": (1, None, int),
    "max_path_depth": (1, 4096, int),
    "max_path_bytes": (1, 65536, int),
    "max_memory_bytes": (0, None, int),
    "max_workers": (0, 1024, int),
    "mmap_threshold": (0, None, int),
}
"""Accepted range for each limit, and the type it must be.

Zero means "no limit" only where a zero floor appears here; elsewhere it is
refused, because a limit of zero is almost always a mistake and silently
means "scan nothing"."""


@dataclass(frozen=True, slots=True)
class Limits:
    """Bounds on what a single scan may consume.

    Immutable, so a detector cannot widen its own budget, and cheaply passed
    between worker processes.

    Defaults are chosen to be invisible on a normal repository and decisive on a
    hostile one. Any value may be lowered by configuration; whether it may be
    raised is an organisation-policy decision, because a repository able to raise
    its own limits can raise them until the protection stops applying.
    """

    # -- File-level --------------------------------------------------------
    max_file_bytes: int = 10 * 1024 * 1024
    """Above this, a file receives literal and entropy matching only, not the
    full regex pass, and the reduction is reported. Ten megabytes is far above
    any hand-written source file, so the ceiling is reached by generated
    artefacts and by deliberate padding, not by real code."""

    max_line_bytes: int = 1 * 1024 * 1024
    """A single line this long is minified output or an attack on the
    line-splitting code. Either way it is not processed line-wise."""

    # -- Scan-level --------------------------------------------------------
    max_total_bytes: int = 5 * 1024 * 1024 * 1024
    max_files: int = 200_000

    max_findings: int = 50_000
    """A hostile repository can otherwise turn a scan into an out-of-memory
    failure by arranging for every line to match. Reaching this cap is itself
    reported, so a truncated result never passes as a complete one."""

    max_dependencies: int = 100_000

    # -- Time --------------------------------------------------------------
    per_file_timeout: float = 5.0
    """Backstop against catastrophic regex backtracking. Pattern validation at
    rule-load time is the primary control; this catches what validation misses,
    which matters because organisations author their own rules."""

    total_timeout: float = 900.0
    """Wall clock for the entire scan. On expiry the engine emits a partial
    result with ``complete=False`` rather than aborting: a partial result a human
    can act on is worth more than a stack trace, and marking it partial is what
    stops it being mistaken for a pass."""

    # -- Archives ----------------------------------------------------------
    max_archive_ratio: int = 200
    """Uncompressed-to-compressed ratio, evaluated incrementally during the
    stream rather than after extraction. Checking afterwards means the bomb has
    already gone off. Ordinary source tarballs sit well under 200:1; a
    decompression bomb is several orders of magnitude above it."""

    max_archive_entries: int = 50_000

    max_archive_depth: int = 3
    """Archives nested inside archives. Beyond this depth the nesting is itself
    the signal, so it is reported rather than skipped."""

    max_uncompressed_bytes: int = 2 * 1024 * 1024 * 1024

    # -- Traversal ---------------------------------------------------------
    max_path_depth: int = 64
    max_path_bytes: int = 4096

    # -- Memory and parallelism -------------------------------------------
    max_memory_bytes: int = 1024 * 1024 * 1024

    max_workers: int = 0
    """0 means automatic: CPU count, capped. Capped rather than unbounded because
    a high-core CI runner spawning one worker per core over a small repository
    spends more time on process startup than on matching."""

    mmap_threshold: int = 1 * 1024 * 1024
    """Above this a file is memory-mapped instead of read. Below it, a plain read
    beats the syscall overhead of mapping."""

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Limits:
        """Build from configuration, rejecting unknown keys.

        Strict by intent. A silently ignored ``max_file_size`` typo means the
        operator believes a limit is in force when it is not, and a control that
        reads as protective while doing nothing is worse than an absent one:
        it stops anybody from looking for the real problem.
        """
        unknown = set(data) - set(cls.__dataclass_fields__)
        if unknown:
            names = ", ".join(sorted(unknown))
            raise ValueError(f"unknown limit(s): {names}")
        return cls(**cls._validated(data))

    def merged(self, **overrides: Any) -> Limits:
        """Return a copy with the non-None overrides applied."""
        clean = {k: v for k, v in overrides.items() if v is not None}
        return replace(self, **self._validated(clean))

    @classmethod
    def _validated(cls, data: dict[str, Any]) -> dict[str, Any]:
        """Check each value's type and range.

        Only keys were checked. So `max_file_bytes: "big"` parsed and failed
        much later inside a comparison, surfacing as "internal error" -- exit 2,
        "this is a bug in cordon", for a typo in the user's own configuration.
        `max_archive_depth: -1` refused every archive and `total_timeout: -5`
        made every scan instantly incomplete, both silently.

        `merged` goes through the same check, because it was a bare
        `dataclasses.replace` and so was the route every command-line override
        took.
        """
        out: dict[str, Any] = {}
        for name, value in data.items():
            floor, ceiling, kind = _LIMIT_RANGES.get(name, (0, None, int))
            # An int is an acceptable float. Requiring `isinstance(value, float)`
            # would reject `total_timeout: 900`, which is how everybody writes it.
            accepted: tuple[type, ...] = (int, float) if kind is float else (int,)
            if isinstance(value, bool) or not isinstance(value, accepted):
                raise ValueError(
                    f"limit {name} must be {'a number' if kind is float else 'an integer'}, "
                    f"got {type(value).__name__}"
                )
            if value < floor or (ceiling is not None and value > ceiling):
                bound = f"{floor} to {ceiling}" if ceiling is not None else f"at least {floor}"
                raise ValueError(f"limit {name}={value} is out of range ({bound})")
            out[name] = value
        return out

    def stricter_of(self, other: Limits) -> Limits:
        """Take the more restrictive value of each field.

        This is how organisation policy clamps a repository's configuration
        without needing a per-field rule for which direction is safe. Every limit
        here is monotonic -- smaller is stricter -- so the minimum is always the
        correct merge.

        ``max_workers`` is the one exception, because 0 means automatic rather
        than unlimited, so taking a minimum would silently disable parallelism.
        """
        values: dict[str, Any] = {}
        for name in self.__dataclass_fields__:
            if name == "max_workers":
                values[name] = self.max_workers or other.max_workers
                continue
            values[name] = min(getattr(self, name), getattr(other, name))
        return Limits(**values)


DEFAULT_LIMITS = Limits()
"""Full-depth profile. Used by CI, pre-push and on-demand scans."""


HOOK_LIMITS = Limits(
    max_file_bytes=2 * 1024 * 1024,
    per_file_timeout=1.0,
    total_timeout=20.0,
    max_files=10_000,
)
"""Pre-commit profile: depth traded for latency, deliberately.

A commit-time guard competes directly with the developer's attention. If it costs
noticeably more than a second, it gets bypassed, and a bypassed guard protects
nothing at all. So the hook profile is tuned to stay imperceptible, and full
depth runs at pre-push and in CI where the wait is already expected.
"""


__all__ = ["DEFAULT_LIMITS", "HOOK_LIMITS", "Limits"]
