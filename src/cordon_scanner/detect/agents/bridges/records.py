"""One internal record per first-party JavaScript file that does any part of the remote-bridge shape.

Read in the worker, as the code model's scores are: the record is a finding no reader sees (`INTERNAL.AGENT.REMOTE_CONTROL.FILE`,
info, operational) whose message is the file's signals (`BridgeShape.encode`). The package step in the parent joins them, decides
and removes every record; the result assembly strips any left. A record is a fact about one file, never a capability label other
rules read.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar, Final

from cordon_scanner.detect.agents.bridges.shape import BridgeShape
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
    from collections.abc import Iterator

    from cordon_scanner.detect.base import FileUnit, ScanContext

_FIRST_PARTY_CODE: Final = (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts")
#: Not the package's own code: its dependencies, tests, fixtures, examples and type declarations.
_NOT_THE_PACKAGE: Final = re.compile(
    r"(?:^|/)(?:node_modules|tests?|__tests__|fixtures?|examples?|spec)/|\.(?:test|spec)\.[cm]?[jt]s$|\.d\.[cm]?ts$"
)


class BridgeRecords:
    RULE: ClassVar[str] = "INTERNAL.AGENT.REMOTE_CONTROL.FILE"
    DETECTOR: ClassVar[str] = "agents"

    @staticmethod
    def first_party(path: str) -> bool:
        member = path.rpartition("!")[2].lower()
        return member.endswith(_FIRST_PARTY_CODE) and _NOT_THE_PACKAGE.search(member) is None

    @classmethod
    def of(cls, unit: FileUnit, ctx: ScanContext) -> Iterator[Finding]:
        """The file's record, when the file does any part of the shape and is the package's own code."""
        if unit.content.is_binary or not cls.first_party(unit.content.path):
            return
        signals = BridgeShape.signals(unit.content.text)
        if signals is None:
            return
        message = BridgeShape.encode(signals)
        lines = BridgeShape.encode_lines(BridgeShape.lines(unit.content.text))
        path = unit.content.path
        yield Finding(
            rule_id=cls.RULE,
            category=Category.OPERATIONAL,
            severity=Severity.INFO,
            confidence=Confidence.CONFIRMED,
            message=message,
            location=Location(path=path),
            evidence=Evidence(
                kind=EvidenceKind.METADATA,
                match_hash=Evidence.hash_bytes(f"{cls.RULE}:{path}:{message}".encode()),
                redaction=RedactionMode.NONE,
                metadata=(("record", message), ("lines", lines)),
            ),
            remediation="",
            explanation=Explanation(
                summary="What one file does of the remote-bridge shape.", matched_rule=cls.RULE
            ),
            risk=NO_RISK,
            detector=cls.DETECTOR,
            always_report=False,
        )


__all__ = ["BridgeRecords"]
