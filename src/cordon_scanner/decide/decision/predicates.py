"""Typed predicates: the only conditions a policy rule can state (design spec 6.1, I11).

A predicate is a map from a field of a closed list to a value. The value is a literal (equality, or
"contains" for a list-valued field), `{"in": [...]}` (or the name of one of the policy's lists),
`{"glob": "pkg*"}`, or for an ordered field a string such as `">=medium"` or `"<3d"`. There are no
expressions, no loops and no regular expressions: a policy is data, and the same table is read the same way
in every runtime. An unknown field, an operator the field does not take, or a value of the wrong type is a
compile error that names the path.

Compiling turns a predicate into a sorted tuple of `Condition`s with every list reference replaced by the
list's values, so a compiled table is self-contained and its digest covers what it will match.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any, ClassVar

from cordon_scanner.contracts.subjects import SubjectKind
from cordon_scanner.decide.decision.evidence import Context, FindingFact
from cordon_scanner.decide.decision.records import JsonRecord, PolicyError


@dataclass(frozen=True, slots=True)
class FieldSpec:
    """One field a predicate may name: its kind and, for an enumeration or an ordered scale, its values."""

    name: str
    kind: str  # enum | ordered | int | text | tags | bool
    values: tuple[str, ...] = ()

    @property
    def is_finding(self) -> bool:
        return self.name.startswith("finding.")


class Fields:
    """The closed list of fields."""

    TABLE: ClassVar[dict[str, FieldSpec]] = {
        spec.name: spec
        for spec in (
            FieldSpec("finding.rule_id", "text"),
            FieldSpec("finding.category", "enum", FindingFact.CATEGORIES),
            FieldSpec("finding.severity", "ordered", FindingFact.SEVERITIES),
            FieldSpec("finding.confidence", "ordered", FindingFact.CONFIDENCES),
            FieldSpec("finding.domain", "text"),
            FieldSpec("subject.kind", "enum", tuple(kind.value for kind in SubjectKind)),
            FieldSpec("subject.ecosystem", "text"),
            FieldSpec("subject.namespace", "text"),
            FieldSpec("subject.tags", "tags"),
            FieldSpec("subject.id", "text"),
            FieldSpec("artifact.digest", "text"),
            FieldSpec("version.age_days", "int"),
            FieldSpec("provenance.slsa_level", "int"),
            FieldSpec("signature.signer", "text"),
            FieldSpec("publisher.age_days", "int"),
            FieldSpec("name.lookalike", "enum", ("present", "absent")),
            FieldSpec("registry.host", "text"),
            FieldSpec("approval", "enum", ("present", "absent")),
            FieldSpec("context.point", "enum", Context.POINTS),
            FieldSpec("context.environment", "text"),
            FieldSpec("context.relation", "enum", Context.RELATIONS),
            FieldSpec("context.actor", "text"),
            FieldSpec("intel.known_malware", "bool"),
            FieldSpec("intel.advisory", "bool"),
        )
    }
    #: The operators of each kind.
    OPERATORS: ClassVar[dict[str, tuple[str, ...]]] = {
        "enum": ("eq", "in"),
        "ordered": ("eq", "in", "ge", "gt", "le", "lt"),
        "int": ("eq", "in", "ge", "gt", "le", "lt"),
        "text": ("eq", "in", "glob"),
        "tags": ("eq", "in", "glob"),
        "bool": ("eq",),
    }
    ORDERINGS: ClassVar[tuple[tuple[str, str], ...]] = (
        (">=", "ge"),
        ("<=", "le"),
        (">", "gt"),
        ("<", "lt"),
    )

    @classmethod
    def spec(cls, name: str, path: str) -> FieldSpec:
        try:
            return cls.TABLE[name]
        except KeyError:
            raise PolicyError(f"{path}.{name}: unknown field") from None


@dataclass(frozen=True, slots=True)
class Condition(JsonRecord):
    """One compiled condition: `field op value`. A list value is a tuple."""

    field: str
    op: str
    value: str | int | bool | tuple[str | int, ...]


@dataclass(frozen=True, slots=True)
class Match:
    """Whether a predicate held, and which findings made it hold (the facts an explanation points at)."""

    matched: bool
    findings: tuple[FindingFact, ...] = ()


class PredicateCompiler:
    """Check a predicate against the field table and write it as conditions."""

    @classmethod
    def compile(
        cls, predicate: Mapping[str, Any] | None, lists: Mapping[str, tuple[str, ...]], path: str
    ) -> tuple[Condition, ...]:
        if predicate is None:
            return ()
        if not isinstance(predicate, Mapping):
            raise PolicyError(f"{path}: a predicate is an object of field: value")
        found = [cls._condition(name, raw, lists, path) for name, raw in predicate.items()]
        return tuple(sorted(found, key=lambda item: (item.field, item.op, repr(item.value))))

    @classmethod
    def _condition(
        cls, name: str, raw: Any, lists: Mapping[str, tuple[str, ...]], path: str
    ) -> Condition:
        spec = Fields.spec(name, path)
        where = f"{path}.{name}"
        op, operand = cls._split(spec, raw, where)
        if op not in Fields.OPERATORS[spec.kind]:
            raise PolicyError(f"{where}: {spec.kind} field does not take {op!r}")
        if op == "in":
            members = cls._members(operand, lists, where)
            return Condition(name, op, tuple(cls._value(spec, item, where) for item in members))
        return Condition(name, op, cls._value(spec, operand, where))

    @classmethod
    def _split(cls, spec: FieldSpec, raw: Any, where: str) -> tuple[str, Any]:
        if isinstance(raw, Mapping):
            if len(raw) != 1:
                raise PolicyError(f"{where}: one operator per field")
            ((op, operand),) = raw.items()
            if op not in ("in", "glob", "eq", "ge", "gt", "le", "lt"):
                raise PolicyError(f"{where}: unknown operator {op!r}")
            return str(op), operand
        if isinstance(raw, str) and spec.kind in ("ordered", "int"):
            for symbol, op in Fields.ORDERINGS:
                if raw.startswith(symbol):
                    return op, raw[len(symbol) :].strip()
        return "eq", raw

    @staticmethod
    def _members(operand: Any, lists: Mapping[str, tuple[str, ...]], where: str) -> tuple[Any, ...]:
        if isinstance(operand, str):
            if operand not in lists:
                raise PolicyError(f"{where}: no list named {operand!r}")
            return lists[operand]
        if isinstance(operand, (list, tuple)) and operand:
            return tuple(operand)
        raise PolicyError(f"{where}: `in` takes a non-empty list or the name of a list")

    @classmethod
    def _value(cls, spec: FieldSpec, value: Any, where: str) -> str | int | bool:
        if spec.kind == "bool":
            if not isinstance(value, bool):
                raise PolicyError(f"{where}: expected true or false")
            return value
        if spec.kind == "int":
            return cls._whole(value, where)
        if spec.kind in ("enum", "ordered"):
            if value not in spec.values:
                raise PolicyError(f"{where}: {value!r} is not one of {', '.join(spec.values)}")
            return str(value)
        if not isinstance(value, str) or not value:
            raise PolicyError(f"{where}: expected a non-empty string")
        return value

    @staticmethod
    def _whole(value: Any, where: str) -> int:
        text = str(value).strip()
        text = text[:-1] if text.endswith("d") else text
        if isinstance(value, bool) or not text.isdigit():
            raise PolicyError(f"{where}: expected a whole number (days may be written `3d`)")
        return int(text)


class PredicateEvaluator:
    """Evaluate conditions against facts."""

    @classmethod
    def holds(cls, condition: Condition, spec: FieldSpec, actual: Any) -> bool:
        """Whether one condition holds for a fact's value; a fact that is not known holds for nothing."""
        if actual is None:
            return False
        if isinstance(actual, tuple):  # a list-valued fact (tags): any element may satisfy it
            return any(cls.holds(condition, spec, item) for item in actual)
        op, value = condition.op, condition.value
        if op == "eq":
            return bool(actual == value)
        if op == "in":
            return actual in value  # type: ignore[operator]
        if op == "glob":
            return fnmatchcase(str(actual), str(value))
        left, right = cls._rank(spec, actual), cls._rank(spec, value)
        return {"ge": left >= right, "gt": left > right, "le": left <= right, "lt": left < right}[
            op
        ]

    @staticmethod
    def _rank(spec: FieldSpec, item: Any) -> int:
        return spec.values.index(item) if spec.kind == "ordered" else int(item)


__all__ = ["Condition", "FieldSpec", "Fields", "Match", "PredicateCompiler", "PredicateEvaluator"]
