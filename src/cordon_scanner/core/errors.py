"""Typed errors, each mapped to an exit code.

The mapping is the point. A pipeline that cannot distinguish "the scanner broke"
from "your code is bad" will eventually be configured to ignore both, so the
error type a caller catches and the code the shell sees are defined in one place
and cannot drift apart.

Exit code contract (see docs/03-INTERFACES.md section 1.3):

    0  clean
    1  findings met the failure policy
    2  scanner error
    3  configuration error
    4  scan incomplete and --fail-on-incomplete was set
"""

from __future__ import annotations

import enum


class ExitCode(enum.IntEnum):
    """Stable API. New codes may be added; existing ones never change meaning."""

    CLEAN = 0
    FINDINGS = 1
    SCANNER_ERROR = 2
    CONFIG_ERROR = 3
    INCOMPLETE = 4


class CordonError(Exception):
    """Base for everything Cordon raises deliberately.

    An exception that is not a subclass of this reaching the CLI is a bug, and
    the CLI reports it as one rather than dressing it up as a scan result.
    """

    exit_code: ExitCode = ExitCode.SCANNER_ERROR

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint
        """What the user should do next. Optional, but an error the user cannot
        act on is a bug report waiting to happen."""


class ConfigError(CordonError):
    """Invalid configuration, invalid policy, or a forbidden override.

    Separate from SCANNER_ERROR because it is actionable by a different person:
    a config error is a human's mistake in a YAML file, a scanner error is ours.
    """

    exit_code = ExitCode.CONFIG_ERROR


class PolicyViolationError(ConfigError):
    """A repository config tried to weaken something organisation policy sets.

    Never silently clamped. Clamping quietly leaves a repository owner
    believing a setting is in force when it is not, which is a worse position
    than a failed build: a control that reads as protective while doing nothing
    also stops anybody from looking for the real gap. The conflict is named
    explicitly so it can be resolved rather than absorbed.
    """


class RulePackError(CordonError):
    """A rule pack is malformed, unsafe, or incompatible with this engine."""

    exit_code = ExitCode.CONFIG_ERROR


class UnsafePatternError(RulePackError):
    """A rule pattern was rejected at load time.

    Rejected at load rather than at match, because a pattern that can hang the
    scanner must never reach a worker. Organisations write their own rules; the
    engine cannot assume they were written carefully.
    """


class SourceError(CordonError):
    """A scan target could not be opened or is not a supported kind."""


class LimitExceeded(CordonError):
    """A resource limit was hit.

    Usually caught and converted into an OPERATIONAL finding rather than
    propagated -- one unreadable file must not abort a whole scan. It propagates
    only for limits that make the entire scan meaningless, such as the total
    byte budget.
    """


class ArchiveError(SourceError):
    """An archive was rejected: bomb ratio, traversal, symlink, or nesting."""


class DetectorError(CordonError):
    """A detector failed.

    Converted to an OPERATIONAL finding naming the detector, because a single
    broken detector must not silently reduce coverage. The scan continues and
    reports itself as incomplete.
    """


__all__ = [
    "ArchiveError",
    "ConfigError",
    "CordonError",
    "DetectorError",
    "ExitCode",
    "LimitExceeded",
    "PolicyViolationError",
    "RulePackError",
    "SourceError",
    "UnsafePatternError",
]
