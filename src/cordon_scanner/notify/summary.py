"""What a notification says about a scan, built only from fields that are safe to send.

A finding's message and evidence never enter a `Summary`: they can quote a masked secret or a line
of source. What enters is the rule id, severity, category, location and fingerprint, the counts by
severity, the target's name without credentials, and the gate's outcome and reason. Every channel
builds its message from this and nothing else.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar

from cordon_scanner.foundation.models import Severity
from cordon_scanner.foundation.targets import TargetName
from cordon_scanner.notify.events import EventEnvelope
from cordon_scanner.version import __version__

if TYPE_CHECKING:
    from cordon_scanner.foundation.models import Finding, ScanResult


@dataclass(frozen=True)
class Summary:
    """What a notification says about a scan."""

    MAX_LISTED: ClassVar[int] = 10
    """Findings named in one message. The rest are counted, never listed."""

    target: str
    revision: str
    reason: str
    exit_code: int
    complete: bool
    counts: dict[str, int]
    listed: tuple[dict[str, Any], ...]
    total: int
    gate: str = "failed"
    """`failed` or `passed`, as the event contract spells it."""
    test: bool = False
    """A message sent by `cordon-scanner notify test`, and marked as one."""

    @staticmethod
    def of(
        result: ScanResult, *, reason: str, exit_code: int, gate: str = "failed", test: bool = False
    ) -> Summary:
        active = [f for f in result.findings if not f.is_suppressed]
        ordered = sorted(active, key=lambda f: (-int(f.severity), f.rule_id, f.location.path))
        counts = Counter(str(f.severity) for f in active)
        return Summary(
            target=TargetName.of(result),
            revision=((result.repository.revision if result.repository else None) or "")[:12],
            reason=reason,
            exit_code=exit_code,
            complete=result.complete,
            counts={str(s): counts.get(str(s), 0) for s in sorted(Severity, reverse=True)},
            listed=tuple(Summary._safe(f) for f in ordered[: Summary.MAX_LISTED]),
            total=len(active),
            gate=gate,
            test=test,
        )

    @staticmethod
    def _safe(finding: Finding) -> dict[str, Any]:
        location = finding.location.package or finding.location.path
        if finding.location.line and not finding.location.package:
            location = f"{location}:{finding.location.line}"
        return {
            "rule_id": finding.rule_id,
            "severity": str(finding.severity),
            "category": str(finding.category),
            "location": location,
            "fingerprint": finding.fingerprint,
        }

    def headline(self) -> str:
        test = "[test] " if self.test else ""
        if self.gate == "passed":
            return f"{test}Cordon: {self.target} passed its gate"
        worst = next((s for s, n in self.counts.items() if n), "info")
        return f"{test}Cordon: {self.target} failed its gate ({worst.upper()})"

    def lines(self) -> list[str]:
        out = [f"{f['severity'].upper()} {f['rule_id']} at {f['location']}" for f in self.listed]
        if self.total > len(self.listed):
            out.append(f"... and {self.total - len(self.listed)} more")
        return out

    def event(self, *, sequence: int) -> dict[str, Any]:
        """The `cordon.event/v1` envelope for this scan."""
        return {
            "schema": EventEnvelope.SCHEMA,
            "type": EventEnvelope.SCAN_COMPLETED,
            "sequence": sequence,
            "source": "cli",
            "scan": {
                "target": self.target,
                "revision": self.revision,
                "gate": self.gate,
                "reason": self.reason,
                "exit_code": self.exit_code,
                "complete": self.complete,
                "counts": self.counts,
                "findings": list(self.listed),
                "total_findings": self.total,
                "engine_version": __version__,
            },
        }

    def context(self) -> str:
        """The one-line footer: counts, completeness, target, revision, version."""
        counts = ", ".join(f"{n} {s}" for s, n in self.counts.items() if n) or "no findings"
        revision = f" @ {self.revision}" if self.revision else ""
        partial = "" if self.complete else " · scan INCOMPLETE"
        return f"{counts}{partial} · {self.target}{revision} · cordon-scanner {__version__}"


__all__ = ["Summary"]
