"""A package that lets a remote party drive the local coding agent or terminal: the package step.

Each first-party JavaScript file of the package leaves one internal record of what it does of three things
(`detect/agents/bridges`); here the records are joined, the package decided, and every record removed. The step runs before the
folds and its finding is added after the verdict, as the code model's is, so the verdict never reads it and no capability label
other rules read is touched.

```
  EXEC  drives a coding agent or a terminal          ┐
  CHAN  an outbound client channel, not loopback only  ├─ in the package's own code, anywhere ──► SUSPECT.AGENT.REMOTE_CONTROL.001
  HIST  names an agent's history store               ┘
  two of the three, or any of them only in tests or dependencies                                ──► nothing
```
The finding says which agent or terminal, which kind of channel and which history store, and nothing the package handles.
"""

from __future__ import annotations

from functools import reduce
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.detect.agents.bridges.shape import BridgeShape, Signals
from cordon_scanner.detect.base import NO_RISK
from cordon_scanner.foundation.models import (
    Category,
    Confidence,
    Evidence,
    EvidenceKind,
    Explanation,
    Finding,
    Location,
    RedactionMode,
    Severity,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

RECORD: str = "INTERNAL.AGENT.REMOTE_CONTROL.FILE"


class RemoteControl:
    """`decide(findings)`: the findings without the records, and the package's finding when it has the whole shape."""

    RULE: ClassVar[str] = "SUSPECT.AGENT.REMOTE_CONTROL.001"
    DETECTOR: ClassVar[str] = "agents"

    @staticmethod
    def joined(records: Sequence[Signals]) -> Signals:
        return reduce(lambda a, b: a | b, records, Signals())

    @classmethod
    def fires(cls, records: Sequence[Signals]) -> bool:
        """An agent or terminal is driven, a client channel is open that is not loopback only, and a history store is named."""
        package = cls.joined(records)
        client = bool(package.chans)
        loopback_only = client and package.loop and not package.remote
        return bool(package.execs) and client and not loopback_only and bool(package.hists)

    @classmethod
    def decide(cls, findings: Sequence[Finding]) -> tuple[list[Finding], list[Finding]]:
        kept = [f for f in findings if f.rule_id != RECORD]
        records = [(f, BridgeShape.decode(f.message)) for f in findings if f.rule_id == RECORD]
        signals = [s for _f, s in records if s is not None]
        if not cls.fires(signals):
            return kept, []
        driving = sorted(f.location.path for f, s in records if s is not None and s.execs)
        return kept, [cls.finding(driving[0], cls.joined(signals))]

    @staticmethod
    def _said(kinds: frozenset[str], order: tuple[str, ...]) -> str:
        words = [BridgeShape.WORDS[k] for k in order if k in kinds]
        return (
            ", ".join(words[:-1]) + (" and " if len(words) > 1 else "") + words[-1] if words else ""
        )

    @classmethod
    def finding(cls, path: str, package: Signals) -> Finding:
        from cordon_scanner.detect.agents.rule_catalogue import RULES

        rule = RULES[cls.RULE]
        execs = cls._said(package.execs, ("sdk", "spawn", "cli", "term"))
        chans = cls._said(package.chans, ("websocket", "socketio", "eventsource", "wslibrary"))
        hists = cls._said(package.hists, ("claude", "codex", "gemini"))
        message = (
            f"{rule.message} This package's code starts {execs}, opens {chans}, and names {hists}."
        )
        return Finding(
            rule_id=cls.RULE,
            category=Category.SUSPICIOUS,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            message=message,
            location=Location(path=path),
            evidence=Evidence(
                kind=EvidenceKind.METADATA,
                match_hash=Evidence.hash_bytes(
                    f"{cls.RULE}:{path}:{BridgeShape.encode(package)}".encode()
                ),
                redaction=RedactionMode.NONE,
                metadata=(("drives", execs), ("channel", chans), ("history", hists)),
            ),
            remediation=rule.remediation,
            explanation=Explanation(summary=rule.title, matched_rule=cls.RULE),
            risk=NO_RISK,
            detector=cls.DETECTOR,
            references=rule.references,
        )


__all__ = ["RemoteControl"]
