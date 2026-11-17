"""Inheritance: how a child policy merges with its parents, and what it may not weaken (design spec 6.2).

A mandatory policy's rules and defaults hold below it: a child may ADD rules and TIGHTEN defaults, and the
compiler rejects, naming the exact field and the parent, a child that

```
  restates a rule of a mandatory parent (by id)      disables one of its rules
  weakens on_incomplete, unresolved or on_gaps       weakens the default outcome or `exceptions`
  loosens max_intel_age or bundle_max_age (or drops it)   adds an ecosystem to warn_until_measured
```

A child that is not under a mandatory parent may override what its parent states.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from cordon_scanner.decide.decision.policy_source import DefaultsSource, Durations
from cordon_scanner.decide.decision.records import PolicyError
from cordon_scanner.decide.decision.table import CompiledPolicy, CompiledRule, Defaults


class RuleMerge:
    """The rules of a child: its parents' rules in order, then its own, minus what it may disable."""

    @classmethod
    def merge(
        cls,
        parents: Sequence[CompiledPolicy],
        own: Sequence[CompiledRule],
        disable: Sequence[str],
    ) -> tuple[CompiledRule, ...]:
        inherited = cls._inherited(parents)
        by_id = {rule.id: rule for rule in inherited}
        for name in disable:
            if name not in by_id:
                raise PolicyError(f"disable.{name}: no inherited rule has this id")
            if by_id[name].mandatory:
                raise PolicyError(
                    f"disable.{name}: a rule of mandatory policy {by_id[name].origin} cannot be disabled"
                )
        kept = [rule for rule in inherited if rule.id not in set(disable)]
        for rule in own:
            if rule.id in by_id and by_id[rule.id].mandatory:
                raise PolicyError(
                    f"rules.{rule.id}: restates a rule of mandatory policy {by_id[rule.id].origin}; "
                    "a child cannot replace or weaken it"
                )
        replaced = {rule.id for rule in own}
        return tuple([rule for rule in kept if rule.id not in replaced] + list(own))

    @staticmethod
    def _inherited(parents: Sequence[CompiledPolicy]) -> list[CompiledRule]:
        seen: dict[str, CompiledRule] = {}
        for parent in parents:
            for rule in parent.rules:
                earlier = seen.get(rule.id)
                if earlier is not None and earlier != rule:
                    raise PolicyError(f"rules.{rule.id}: two parents define it differently")
                seen.setdefault(rule.id, rule)
        return list(seen.values())


class DefaultsMerge:
    """The defaults of a child over those of its parents."""

    @classmethod
    def merge(
        cls,
        parents: Sequence[CompiledPolicy],
        stated: DefaultsSource | None,
        locked_by: Sequence[str],
    ) -> Defaults:
        base = cls._parents(parents)
        child = stated or DefaultsSource()
        who = ", ".join(locked_by)
        strict = bool(locked_by)
        return Defaults(
            on_incomplete=cls._incomplete(base.on_incomplete, child.on_incomplete, strict, who),
            unresolved=cls._level(
                base.unresolved, child.unresolved, Defaults.STRICTNESS, "unresolved", strict, who
            ),
            on_gaps=cls._level(
                base.on_gaps, child.on_gaps, Defaults.STRICTNESS, "on_gaps", strict, who
            ),
            exceptions=cls._level(
                base.exceptions, child.exceptions, Defaults.EXCEPTIONS, "exceptions", strict, who
            ),
            default=cls._level(
                base.default, child.default, Defaults.OUTCOMES, "default", strict, who
            ),
            max_intel_age_s=cls._age(
                base.max_intel_age_s, child.max_intel_age, "max_intel_age", strict, who
            ),
            bundle_max_age_s=cls._age(
                base.bundle_max_age_s, child.bundle_max_age, "bundle_max_age", strict, who
            ),
            warn_until_measured=cls._measured(
                base.warn_until_measured, child.warn_until_measured, strict, who
            ),
            clock_bucket_s=base.clock_bucket_s
            if child.clock_bucket_s is None
            else child.clock_bucket_s,
        )

    @staticmethod
    def _parents(parents: Sequence[CompiledPolicy]) -> Defaults:
        """The stricter of the parents' defaults, field by field; the library's defaults when there is none."""
        if not parents:
            return Defaults(on_incomplete={"*": "block"})
        merged = parents[0].defaults
        for parent in parents[1:]:
            other = parent.defaults
            merged = Defaults(
                on_incomplete=DefaultsMerge._stricter_map(
                    merged.on_incomplete, other.on_incomplete
                ),
                unresolved=max(merged.unresolved, other.unresolved, key=Defaults.STRICTNESS.index),
                on_gaps=max(merged.on_gaps, other.on_gaps, key=Defaults.STRICTNESS.index),
                exceptions=max(merged.exceptions, other.exceptions, key=Defaults.EXCEPTIONS.index),
                default=max(merged.default, other.default, key=Defaults.OUTCOMES.index),
                max_intel_age_s=DefaultsMerge._smaller(
                    merged.max_intel_age_s, other.max_intel_age_s
                ),
                bundle_max_age_s=DefaultsMerge._smaller(
                    merged.bundle_max_age_s, other.bundle_max_age_s
                ),
                warn_until_measured=tuple(
                    sorted(set(merged.warn_until_measured) & set(other.warn_until_measured))
                ),
                clock_bucket_s=merged.clock_bucket_s,
            )
        return merged

    @staticmethod
    def _smaller(left: int | None, right: int | None) -> int | None:
        if left is None or right is None:
            return left if right is None else right
        return min(left, right)

    @staticmethod
    def _stricter_map(left: dict[str, str], right: dict[str, str]) -> dict[str, str]:
        out = dict(left)
        for environment, level in right.items():
            if environment not in out or Defaults.STRICTNESS.index(
                level
            ) > Defaults.STRICTNESS.index(out[environment]):
                out[environment] = level
        return out

    @classmethod
    def _incomplete(
        cls, base: dict[str, str], stated: Any, strict: bool, who: str
    ) -> dict[str, str]:
        if stated is None:
            return dict(base)
        wanted = {"*": stated} if isinstance(stated, str) else dict(stated)
        out = dict(base)
        for environment, level in wanted.items():
            if level not in Defaults.STRICTNESS:
                raise PolicyError(
                    f"defaults.on_incomplete.{environment}: {level!r} is not one of warn, review, block"
                )
            inherited = base.get(environment, base["*"])
            if strict and Defaults.STRICTNESS.index(level) < Defaults.STRICTNESS.index(inherited):
                raise PolicyError(
                    f"defaults.on_incomplete.{environment}: {level} is weaker than {inherited}, "
                    f"which mandatory {who} requires"
                )
            out[environment] = level
        if strict:
            for environment, level in base.items():
                if Defaults.STRICTNESS.index(
                    out.get(environment, out["*"])
                ) < Defaults.STRICTNESS.index(level):
                    raise PolicyError(
                        f"defaults.on_incomplete.{environment}: weaker than mandatory {who} requires"
                    )
        return out

    @classmethod
    def _level(
        cls,
        base: str,
        stated: str | None,
        scale: tuple[str, ...],
        name: str,
        strict: bool,
        who: str,
    ) -> str:
        if stated is None:
            return base
        if stated not in scale:
            raise PolicyError(f"defaults.{name}: {stated!r} is not one of {', '.join(scale)}")
        if strict and scale.index(stated) < scale.index(base):
            raise PolicyError(
                f"defaults.{name}: {stated} is weaker than {base}, which mandatory {who} requires"
            )
        return stated

    @classmethod
    def _age(cls, base: int | None, stated: Any, name: str, strict: bool, who: str) -> int | None:
        if stated is None:
            return base
        if stated == "none":
            if strict and base is not None:
                raise PolicyError(
                    f"defaults.{name}: dropping the limit is looser than {base}s, which mandatory {who} requires"
                )
            return None
        seconds = Durations.seconds(stated, f"defaults.{name}")
        if strict and base is not None and seconds > base:
            raise PolicyError(
                f"defaults.{name}: {seconds}s is looser than {base}s, which mandatory {who} requires"
            )
        return seconds

    @classmethod
    def _measured(
        cls, base: tuple[str, ...], stated: tuple[str, ...] | None, strict: bool, who: str
    ) -> tuple[str, ...]:
        if stated is None:
            return base
        added = sorted(set(stated) - set(base))
        if strict and added:
            raise PolicyError(
                f"defaults.warn_until_measured: adds {added[0]!r}, which mandatory {who} does not list "
                "(a longer list turns blocks into reviews)"
            )
        return tuple(sorted(set(stated)))


__all__ = ["DefaultsMerge", "RuleMerge"]
