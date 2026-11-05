"""The terms the infrastructure policy tables are written in: the severities they grade with, and the
presence gate an entry uses when a control applies only where another setting is present.
"""

from __future__ import annotations

from typing import NamedTuple

from cordon_scanner.foundation.models import Severity

HIGH = Severity.HIGH

MEDIUM = Severity.MEDIUM

LOW = Severity.LOW


class PresenceGate(NamedTuple):
    """When an absent attribute is worth reporting, and how to show it.

    `when` is what the block must also contain; `sample` is the line that puts
    it into the generated examples, so the policy proves itself against a block
    in the mode it applies to; `qualifier` names that mode in the finding.
    """

    when: tuple[str, ...]
    sample: str
    qualifier: str


__all__ = ["HIGH", "LOW", "MEDIUM", "PresenceGate"]
