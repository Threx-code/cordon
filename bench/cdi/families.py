"""What a family is, and how many independent ones a set of malware units really holds.

    unit   {"digest", "content", "campaign", "publisher"}: the content (or behaviour) fingerprint, the campaign fingerprint
           and who published it, each a plain string; a unit with none of a fingerprint carries an empty one.

A family is keyed by BOTH fingerprints: two units are one family when they share a content fingerprint or a campaign
fingerprint, and so are the units any chain of such pairs joins. A shared payload digest and a shared code-reuse cluster
each join units that a name or a version alone would keep apart.

How many families a claim rests on is a different count from how many keys there are. Three families with one publisher
behind them are one actor wearing three names, so families that share a publisher count as one, and a claim of "three
families" is met only by three of those, with three distinct publishers. The rule's version is written into every fold, so
a number counted under one rule is never read against another.
"""

from __future__ import annotations

from typing import Any, ClassVar, Final

RULE_VERSION: Final = "family-rule/1"


class _Join:
    """A disjoint-set over strings."""

    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, item: str) -> str:
        self.parent.setdefault(item, item)
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def join(self, a: str, b: str) -> None:
        self.parent[self.find(a)] = self.find(b)


class Families:
    NEEDED: ClassVar[int] = 3
    """The independent families, and the distinct publishers, a "three families" claim needs."""

    @staticmethod
    def keyed(units: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        """The units grouped into families by their content and campaign fingerprints, each family named by its first
        digest. A unit with neither fingerprint is a family of its own."""
        join = _Join()
        for unit in units:
            digest = str(unit["digest"])
            join.find(f"u:{digest}")
            for kind in ("content", "campaign"):
                if unit.get(kind):
                    join.join(f"u:{digest}", f"{kind}:{unit[kind]}")
        groups: dict[str, list[dict[str, Any]]] = {}
        for unit in units:
            groups.setdefault(join.find(f"u:{unit['digest']}"), []).append(unit)
        named: dict[str, list[dict[str, Any]]] = {}
        for members in groups.values():
            named[min(str(m["digest"]) for m in members)] = members
        return named

    @classmethod
    def independent(cls, units: list[dict[str, Any]]) -> list[list[str]]:
        """The families that count as separate: families that share a publisher are merged. Each is the sorted digests
        of its units."""
        families = cls.keyed(units)
        join = _Join()
        for name, members in families.items():
            join.find(f"f:{name}")
            for member in members:
                if member.get("publisher"):
                    join.join(f"f:{name}", f"p:{member['publisher']}")
        merged: dict[str, list[str]] = {}
        for name, members in families.items():
            merged.setdefault(join.find(f"f:{name}"), []).extend(str(m["digest"]) for m in members)
        return sorted(sorted(group) for group in merged.values())

    @classmethod
    def counts(cls, units: list[dict[str, Any]]) -> dict[str, Any]:
        """What a fold records: the rule's version, the families by key, the independent ones and the publishers."""
        return {
            "family_rule": RULE_VERSION,
            "families": len(cls.keyed(units)),
            "independent_families": len(cls.independent(units)),
            "publishers": len({u["publisher"] for u in units if u.get("publisher")}),
        }

    @classmethod
    def meets_claim(cls, units: list[dict[str, Any]]) -> bool:
        """Whether the units rest "three families": three independent ones, behind three distinct publishers."""
        counted = cls.counts(units)
        return counted["independent_families"] >= cls.NEEDED and counted["publishers"] >= cls.NEEDED
