"""A delivered rule that reports and blocks nothing: the demotion to warn, and what says why.

A rule is demoted when it fired on a bundled benign fixture as its pack loaded, or when the device's own record says it blocked too large a share of local scans. A demoted rule still runs and still
reports, at low severity and confidence and in the policy category, so it is seen and decides nothing; its message says it was demoted. The pack carries each demoted rule with the reason, and the
scan's result counts them.
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from cordon_scanner.foundation.models import Category, Confidence, Severity

if TYPE_CHECKING:
    from collections.abc import Mapping

    from cordon_scanner.rules.pack import RulePack


class RuleDemotion:
    @staticmethod
    def wording(why: str) -> str:
        """How a finding says why it is a warning: a reason in the form `held by <role> until <date>: <reason>` reads `held at warn by <role> until <date>: <reason>`; any other reads `demoted to warn: <reason>`."""
        if why.startswith("held by "):
            return "held at warn " + why[len("held ") :]
        return f"demoted to warn: {why}"

    @staticmethod
    def apply(pack: RulePack, reasons: Mapping[str, str]) -> RulePack:
        """`pack` with each rule named in `reasons` demoted to warn, and the reasons recorded on the pack."""
        if not reasons:
            return pack
        rules, recorded = [], []
        for compiled in pack.rules:
            why = reasons.get(compiled.rule.id)
            if why is None:
                rules.append(compiled)
                continue
            recorded.append((compiled.rule.id, why))
            rule = replace(
                compiled.rule,
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                category=Category.POLICY,
                message=f"[{RuleDemotion.wording(why)}] {compiled.rule.message}",
            )
            rules.append(replace(compiled, rule=rule))
        return replace(pack, rules=tuple(rules), demoted=(*pack.demoted, *recorded))


__all__ = ["RuleDemotion"]
