"""cordon-rule's lazy build: rules a pack cache kept, each built the first time it runs.

They were built once already, without error, when they were kept (`pack_cache`). Most of a large
pack's rules never run on a given file, since their strings do not occur, so a load builds only what
a scan needs.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from cordon_scanner.detect.binary.rule_engine.build import Builder, Frame, Scope
from cordon_scanner.detect.binary.rule_engine.syntax import RuleDef


class LazyBuild:
    """Gives each rule a `run` that builds it on its first call."""

    @staticmethod
    def stubs(rules: list[RuleDef], modules: dict[str, Any], externals: dict[str, Any]) -> None:
        names = [rule.name for rule in rules]
        for position, rule in enumerate(rules):
            rule.width = 0
            rule.run = LazyBuild._on_first_run(rules, modules, externals, names, position)

    @staticmethod
    def _on_first_run(
        rules: list[RuleDef],
        modules: dict[str, Any],
        externals: dict[str, Any],
        names: list[str],
        position: int,
    ) -> Callable[[Frame], bool]:
        rule = rules[position]

        def run(frame: Frame) -> bool:
            builder = Builder(rules, modules, externals)
            builder.before, builder.scope = set(names[:position]), Scope(rule)
            kind, fn = builder.node(rule.condition)
            Builder.as_test(kind, "a condition")
            rule.run, rule.width = Builder.truth(fn), builder.scope.width
            frame.env = [None] * rule.width
            return bool(rule.run(frame))

        return run


__all__ = ["LazyBuild"]
