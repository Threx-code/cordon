"""`PolicyCompiler`: a policy source and its parents to a compiled, sealed decision table (design spec 6.3).

Steps: check the source's own fields, resolve its lists, compile each rule's predicates against the closed
field table, merge with the parents (`merge.py`), and seal the result with its digest. The same source and
parents give the same bytes and the same `sha256`.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, ClassVar

from cordon_scanner.contracts.obligations import Obligations
from cordon_scanner.contracts.reason_codes import ReasonCodes
from cordon_scanner.decide.decision.merge import DefaultsMerge, RuleMerge
from cordon_scanner.decide.decision.outcome import States
from cordon_scanner.decide.decision.policy_source import PolicySource, RuleSource
from cordon_scanner.decide.decision.predicates import PredicateCompiler
from cordon_scanner.decide.decision.records import Instants, PolicyError
from cordon_scanner.decide.decision.table import CompiledPolicy, CompiledRule


class PolicyCompiler:
    #: The reason a `require` or `when` on one of these fields gives when the rule does not name one.
    REASONS: ClassVar[dict[str, str]] = {
        "provenance.slsa_level": "R500",
        "signature.signer": "R501",
        "version.age_days": "R503",
        "approval": "R700",
    }

    @classmethod
    def compile(
        cls, source: PolicySource, parents: Sequence[CompiledPolicy] = ()
    ) -> CompiledPolicy:
        """The sealed policy for `source` under `parents` (root first). Raises `PolicyError` naming the path."""
        cls._parents(source, parents)
        lists = cls._lists(source, parents)
        locked_by = cls._locked_by(parents)
        own = tuple(cls._rule(rule, lists, source) for rule in cls._unique(source.rules))
        if source.expires_at is not None:
            Instants.parse(source.expires_at)
        policy = CompiledPolicy(
            id=source.id,
            version=source.version,
            sha256="sha256:" + "0" * 64,
            defaults=DefaultsMerge.merge(parents, source.defaults, locked_by),
            scope=source.scope,
            chain=cls._chain(parents),
            locked_by=locked_by,
            mandatory=source.mandatory,
            rules=RuleMerge.merge(parents, own, source.disable),
            lists={name: list(values) for name, values in sorted(lists.items())},
            expires_at=source.expires_at,
            prev_sha=source.prev_sha,
        )
        return policy.sealed()

    # -- the parts -------------------------------------------------------------------------------

    @staticmethod
    def _parents(source: PolicySource, parents: Sequence[CompiledPolicy]) -> None:
        if tuple(parent.id for parent in parents) != source.extends:
            raise PolicyError(
                f"extends: lists {list(source.extends)} but the parents given are "
                f"{[parent.id for parent in parents]}"
            )
        for parent in parents:
            parent.verify()
            if source.scope[: len(parent.scope)] != parent.scope:
                raise PolicyError(
                    f"scope: {list(source.scope)} is not inside the scope of {parent.id}"
                )

    @staticmethod
    def _lists(
        source: PolicySource, parents: Sequence[CompiledPolicy]
    ) -> dict[str, tuple[str, ...]]:
        found: dict[str, tuple[str, ...]] = {}
        for parent in parents:
            for name, values in (parent.lists or {}).items():
                found[name] = tuple(values)
        for name, values in (source.lists or {}).items():
            if not isinstance(values, (list, tuple)) or not all(
                isinstance(item, str) for item in values
            ):
                raise PolicyError(f"lists.{name}: expected a list of strings")
            found[name] = tuple(values)
        return found

    @staticmethod
    def _locked_by(parents: Sequence[CompiledPolicy]) -> tuple[str, ...]:
        found: list[str] = []
        for parent in parents:
            for name in (*parent.locked_by, *([parent.id] if parent.mandatory else [])):
                if name not in found:
                    found.append(name)
        return tuple(found)

    @staticmethod
    def _chain(parents: Sequence[CompiledPolicy]) -> tuple[str, ...]:
        found: list[str] = []
        for parent in parents:
            for name in (*parent.chain, parent.id):
                if name not in found:
                    found.append(name)
        return tuple(found)

    @staticmethod
    def _unique(rules: Sequence[RuleSource]) -> Sequence[RuleSource]:
        seen: set[str] = set()
        for rule in rules:
            if rule.id in seen:
                raise PolicyError(f"rules.{rule.id}: the id is used twice in this policy")
            seen.add(rule.id)
        return rules

    @classmethod
    def _rule(
        cls, rule: RuleSource, lists: Mapping[str, tuple[str, ...]], source: PolicySource
    ) -> CompiledRule:
        where = f"rules.{rule.id}"
        applies = PredicateCompiler.compile(rule.applies_to, lists, f"{where}.applies_to")
        when = PredicateCompiler.compile(rule.when, lists, f"{where}.when")
        require = PredicateCompiler.compile(rule.require, lists, f"{where}.require")
        cls._shape(rule, when, require, where)
        reason = cls._reason(rule, when, require, where)
        for code in rule.obligations:
            if not Obligations.is_registered(code):
                raise PolicyError(f"{where}.obligations: {code!r} is not a registered obligation")
        return CompiledRule(
            id=rule.id,
            tier=rule.tier,
            then=rule.then,
            origin=source.id,
            mandatory=source.mandatory,
            applies_to=applies,
            when=when,
            require=require,
            reason=reason,
            obligations=tuple(rule.obligations),
        )

    @staticmethod
    def _shape(
        rule: RuleSource, when: tuple[Any, ...], require: tuple[Any, ...], where: str
    ) -> None:
        """What each tier must state: a deny rule a `when` and no `require`; a require rule one of them; an allow rule
        an outcome that allows."""
        if rule.tier == "deny":
            if not when or require:
                raise PolicyError(f"{where}: a deny rule states `when` and no `require`")
            if rule.then not in ("block", "review"):
                raise PolicyError(f"{where}.then: a deny rule blocks or sends to review")
        elif rule.tier == "require":
            if not when and not require:
                raise PolicyError(f"{where}: a require rule states `when` or `require`")
            if rule.then not in ("block", "review"):
                raise PolicyError(f"{where}.then: a require rule blocks or sends to review")
        else:
            if require:
                raise PolicyError(f"{where}: an allow rule states `when`, not `require`")
            if rule.then not in ("allow", "allow_with_conditions"):
                raise PolicyError(f"{where}.then: an allow rule allows, with or without conditions")

    @classmethod
    def _reason(
        cls, rule: RuleSource, when: tuple[Any, ...], require: tuple[Any, ...], where: str
    ) -> str | None:
        if rule.reason is not None:
            if not ReasonCodes.is_registered(rule.reason):
                raise PolicyError(
                    f"{where}.reason: {rule.reason!r} is not a registered reason code"
                )
            return rule.reason
        if rule.tier == "allow":
            return None
        fields = [item.field for item in (*require, *when)]
        for field in fields:
            if field in cls.REASONS:
                return cls.REASONS[field]
        if rule.tier == "deny" and any(field.startswith("finding.") for field in fields):
            return None  # chosen from the matched findings when the rule fires
        raise PolicyError(
            f"{where}.reason: a reason code is needed (it cannot be inferred from the fields)"
        )

    @staticmethod
    def states_of(then: str) -> str:
        return {
            "allow": States.ALLOW,
            "allow_with_conditions": States.ALLOW_WITH_CONDITIONS,
            "review": States.REVIEW,
            "block": States.BLOCK,
        }[then]


__all__ = ["PolicyCompiler"]
