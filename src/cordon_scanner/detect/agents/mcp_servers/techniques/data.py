"""The rows of the technique tables, read from the JSON files shipped beside the rule packs.

Each row names a technique and carries, as inert fixtures, the shapes it detects: a reverse shell, a fetched description,
a hook that downloads and runs. Those shapes are data, not code: kept in `rules/builtin/mcp-techniques-<table>.json`
with the rule packs' own test cases, they are not read as this package's source by a scan of an installation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, ClassVar

from cordon_scanner.detect.agents.mcp_servers.techniques.technique import Fixture, Technique
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

    @staticmethod
    def _fixtures(entries: list[list[str]]) -> tuple[Fixture, ...]:
        return tuple((suffix, text) for suffix, text in entries)

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
            positive=cls._fixtures(entry["positive"]),
            negative=cls._fixtures(entry["negative"]),
        )
