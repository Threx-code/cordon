"""The exported decision, evaluated in Python over the facts document (row BP-6-5): the reference the two exports are checked against.

This is the semantics the Rego and Cedar exports carry, written once more in plain code over `ExportFacts`' JSON and an
`ExportTable`, with none of `decide()`'s own machinery. It is what runs in the fast unit test, beside the real engines that run in
the container test: the three must agree with `decide()` on every recorded case.

```
hard stop                                   -> BLOCK
shortfall (a fact of the call)              -> the level the policy sets for it in this environment (warn raises nothing)
asking rules (deny and require) that fired -> the strictest `then` among them, and the allow rules and the default are not consulted
else allow rules that fired                 -> ALLOW_WITH_CONDITIONS if any says so, else ALLOW
else                                        -> the policy's default
the state is the strictest of all of these
```
A rule fires when its `applies_to` holds, its `when` holds, and its `require` does not (an empty `require` never holds). A part
that names finding fields holds when ONE finding satisfies all of them; a part with none needs no finding.
"""

from __future__ import annotations

from fnmatch import fnmatchcase
from typing import Any, ClassVar

from cordon_scanner.decide.decision.evidence import FindingFact
from cordon_scanner.decide.decision.predicates import Condition
from cordon_scanner.decide.export.table import ExportedRule, ExportTable


class ExportReference:
    STATES: ClassVar[tuple[str, ...]] = ("ALLOW", "ALLOW_WITH_CONDITIONS", "REVIEW", "BLOCK")
    ORDERED: ClassVar[dict[str, tuple[str, ...]]] = {
        "finding.severity": FindingFact.SEVERITIES,
        "finding.confidence": FindingFact.CONFIDENCES,
    }

    @classmethod
    def evaluate(cls, table: ExportTable, facts: dict[str, Any]) -> tuple[str, tuple[str, ...]]:
        """(the state, the ids of the rules that decided it) for a facts document."""
        if facts["hard_stop"]:
            return "BLOCK", ()
        rank = 0
        for name, present in facts["shortfalls"].items():
            if present:
                rank = max(rank, ExportTable.LEVEL_RANK[table.level_of(name, facts["environment"])])
        fired = [rule for rule in table.rules if cls._fires(rule, facts)]
        asking = [rule for rule in fired if rule.asks_for_more]
        allows = [rule for rule in fired if not rule.asks_for_more]
        if asking:
            decided = asking
            rank = max(rank, *(ExportTable.THEN_RANK[rule.then] for rule in asking))
        elif allows:
            decided = allows
            rank = max(rank, *(ExportTable.THEN_RANK[rule.then] for rule in allows))
        else:
            decided = []
            rank = max(rank, ExportTable.THEN_RANK[table.default])
        return cls.STATES[rank], tuple(sorted(rule.id for rule in decided))

    @classmethod
    def _fires(cls, rule: ExportedRule, facts: dict[str, Any]) -> bool:
        return (
            cls._part(rule.applies_to, facts)
            and cls._part(rule.when, facts)
            and not (rule.require and cls._part(rule.require, facts))
        )

    @classmethod
    def _part(cls, conditions: tuple[Condition, ...], facts: dict[str, Any]) -> bool:
        about_findings = [item for item in conditions if ExportTable.is_finding(item)]
        if any(
            not ExportTable.is_finding(item)
            and not cls._holds(item, facts["values"].get(item.field))
            for item in conditions
        ):
            return False
        if not about_findings:
            return True
        return any(
            all(
                cls._holds(item, cls._finding_value(finding, item.field)) for item in about_findings
            )
            for finding in facts["findings"]
        )

    @staticmethod
    def _finding_value(finding: dict[str, Any], field: str) -> Any:
        return finding[field.partition(".")[2]]

    @classmethod
    def _holds(cls, condition: Condition, actual: Any) -> bool:
        if actual is None:
            return False
        if isinstance(actual, list):  # a list-valued fact: any element may satisfy it
            return any(cls._holds(condition, item) for item in actual)
        op, value = condition.op, condition.value
        if op == "eq":
            return bool(actual == value)
        if op == "in":
            return actual in value  # type: ignore[operator]
        if op == "glob":
            return fnmatchcase(str(actual), str(value))
        scale = cls.ORDERED.get(condition.field)
        left = scale.index(actual) if scale else int(actual)
        right = scale.index(value) if scale else int(value)  # type: ignore[arg-type]
        return {"ge": left >= right, "gt": left > right, "le": left <= right, "lt": left < right}[
            op
        ]


__all__ = ["ExportReference"]
