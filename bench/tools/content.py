"""The content rule moved to `cordon_scanner.contracts.content_rule` (design spec M0): the bench, the
scanner and the measurement service share one definition of what "blocked" means. This module is the
names the bench's scripts already import, unchanged."""

from __future__ import annotations

from cordon_scanner.contracts.content_rule import (
    CONTENT_DETECTORS,
    CONTENT_GAPS,
    INTEL_DETECTORS,
    INTEL_MARKERS,
    INTEL_RULE_PREFIXES,
    Content,
)

__all__ = [
    "CONTENT_DETECTORS",
    "CONTENT_GAPS",
    "INTEL_DETECTORS",
    "INTEL_MARKERS",
    "INTEL_RULE_PREFIXES",
    "Content",
]
