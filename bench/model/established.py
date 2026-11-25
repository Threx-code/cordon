"""Benign training only from established packages (SI-O2, LL-11): the guardrail that keeps a fresh upload out of the legitimate side.

A package counts as established when its first registry publication is at least `MIN_DAYS` old, or its name is on a list the scanner ships
(the popular names, or the names known to be real). A package with no recorded first publication and on no list is not established: an
absence is never read as age. The trainer reads it where benign rows enter (`VerdictTrain.load`, with `--established`)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, ClassVar

from cordon_scanner.intel.registries.popular import PackageIntel
from cordon_scanner.intel.registries.real import RealPackages

if TYPE_CHECKING:
    from pathlib import Path


class Established:
    MIN_DAYS: ClassVar[int] = 90

    @classmethod
    def accepts(cls, ecosystem: str, name: str, first_published: str | None, now: datetime | None = None) -> bool:
        """Whether the package `name` of `ecosystem` may be a benign training row."""
        if name in PackageIntel.POPULAR_PACKAGES.get(ecosystem, frozenset()) or name in RealPackages.real_packages(ecosystem):
            return True
        born = cls._time(first_published)
        return born is not None and born <= (now or datetime.now(UTC)) - timedelta(days=cls.MIN_DAYS)

    @staticmethod
    def _time(text: str | None) -> datetime | None:
        if not text:
            return None
        try:
            found = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
        return found if found.tzinfo else found.replace(tzinfo=UTC)

    @staticmethod
    def load(path: Path) -> dict[str, str]:
        """`file -> first publication`, from a JSON-lines file of `{"file": ..., "first_published": ...}`; a line that is not one is skipped."""
        ages: dict[str, str] = {}
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict) and isinstance(row.get("file"), str) and isinstance(row.get("first_published"), str):
                ages[row["file"]] = row["first_published"]
        return ages
