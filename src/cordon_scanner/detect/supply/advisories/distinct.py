"""The advisory records about one dependency, one per thing they say.

Two sources often record the same fact under their own identifiers: OSV's `MAL-` record and a
registry's own advisory both say `flatmap-stream 0.1.1` is malicious; a GHSA and a PYSEC record
both describe one CVE. Reported once each, a user reads two findings for one problem and a policy
counts it twice. So:

- every malicious record about the release is one finding: a release is malicious once;
- vulnerability records that share an identifier or an alias, directly or through each other,
  are one vulnerability.

The record kept for a group is the one that says the most: the highest severity, an exact version
list over a range (a range's match is `HIGH` confidence, a listed version's `CONFIRMED`), then the
smallest identifier, so the choice is the same under every hash seed. It carries every other
identifier in the group as an alias, so the finding still names each, and the exploited catalogues,
which key on CVE aliases, see all of them.
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from collections.abc import Iterable

    from cordon_scanner.intel.base import AdvisoryRecord

_RANK = {"low": 1, "moderate": 2, "medium": 2, "high": 3, "critical": 4}


class DistinctAdvisories:
    """`DistinctAdvisories.of(records)`: the records about one dependency, one per fact."""

    @staticmethod
    def of(records: Iterable[AdvisoryRecord]) -> list[AdvisoryRecord]:
        """One record per malicious release and per vulnerability, in the order first seen."""
        records = list(records)
        groups: list[list[AdvisoryRecord]] = []
        malicious: list[AdvisoryRecord] = []
        owner: dict[str, int] = {}
        for record in records:
            if record.malicious:
                if not malicious:
                    groups.append(malicious)
                malicious.append(record)
                continue
            names = DistinctAdvisories._names(record)
            found = sorted({owner[n] for n in names if n in owner})
            if not found:
                index = len(groups)
                groups.append([record])
            else:
                # The first group absorbs every other group this record links to it.
                index = found[0]
                groups[index].append(record)
                for other in found[1:]:
                    groups[index].extend(groups[other])
                    for member in groups[other]:
                        for name in DistinctAdvisories._names(member):
                            owner[name] = index
                    groups[other] = []
            for name in names:
                owner[name] = index
        return [DistinctAdvisories._one(group) for group in groups if group]

    @staticmethod
    def _names(record: AdvisoryRecord) -> set[str]:
        return {n for n in (record.identifier, *record.aliases) if n}

    @staticmethod
    def _one(group: list[AdvisoryRecord]) -> AdvisoryRecord:
        if len(group) == 1:
            return group[0]
        kept = min(
            group,
            key=lambda r: (-_RANK.get(r.severity.lower(), 3), r.is_range, r.identifier),
        )
        # A record is a protocol (`intel/base.py`); the shipped one is a frozen dataclass. One that
        # is not keeps its own identifiers, as before.
        if getattr(kept, "__dataclass_fields__", None) is None:
            return kept
        others = sorted(
            {n for r in group for n in DistinctAdvisories._names(r)} - {kept.identifier}
        )
        aliases = tuple(dict.fromkeys((*kept.aliases, *others)))
        return cast("AdvisoryRecord", replace(cast("Any", kept), aliases=aliases))


__all__ = ["DistinctAdvisories"]
