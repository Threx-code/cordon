"""The rows of the technique tables, read from the JSON files shipped beside the rule packs.

Each row names a technique and holds what the reader needs to find it: the patterns, what else must be there, what makes
it something else, the grade and the words a user reads. A row holds no example of the attack: the fixtures that exercise
a row are test data (`tests/unit/detect/agents/mcp_servers/technique_fixtures.json`), so nothing shipped carries a working
command line, and a scan of an installation reads this package as it reads any other.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, ClassVar

from cordon_scanner.detect.agents.mcp_servers.techniques.technique import Technique
from cordon_scanner.foundation.models import Confidence, Severity
from cordon_scanner.foundation.paths import PackagePaths


class TechniqueData:
    """`load()`: every row of every table, in the order of `TABLES`."""

    TABLES: ClassVar[tuple[str, ...]] = ("core", "extra", "persist", "rugpull")

    @staticmethod
    def directory() -> Path:
        """Where the tables ship: beside the bundled packs."""
        return PackagePaths.root() / "rules" / "builtin"

    @classmethod
    def load(cls) -> tuple[Technique, ...]:
        """The rows of the shipped tables. A missing or unreadable table is an error, not an empty table: a scan
        that reads fewer techniques than it reports would say less than it claims."""
        rows: list[Technique] = []
        for table in cls.TABLES:
            path = cls.directory() / f"mcp-techniques-{table}.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            rows.extend(cls._row(entry) for entry in document)
        return tuple(rows)

    @classmethod
    def _row(cls, entry: dict[str, Any]) -> Technique:
        return Technique(
            rule_id=entry["rule_id"],
            family=entry["family"],
            title=entry["title"],
            message=entry["message"],
            remediation=entry["remediation"],
            patterns=tuple(entry["patterns"]),
            requires=tuple(entry["requires"]),
            unless=tuple(entry["unless"]),
            at_least=entry["at_least"],
            severity=Severity[entry["severity"]],
            confidence=Confidence[entry["confidence"]],
        )
