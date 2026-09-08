"""The rules a detector owns, declared as data.

The rule loader opens with a claim: detection rules are "data, not code ...
reviewable by a security team without reading Python". It is true of the five
YAML packs and was false of the rules that fire most often in practice. The
secret, container, CI, IaC, obfuscation and dependency rules were emitted from
Python literals, appeared in no pack, and `cordon rules show
SECRET.AWS.ACCESS_KEY.001` answered "no such rule" for a rule the tool emits.

The consequences were concrete rather than stylistic. An organisation could not
see what would run, could not read a rule's message and remediation without
opening the source, and could not turn one off without patching the installed
package.

This module does not pretend those rules are YAML. It makes them *declared*:
every detector publishes a descriptor for each rule it can emit, the CLI lists
and shows them alongside pack rules, and configuration can disable any of them
by id. What a YAML pack additionally guarantees -- mandatory test samples,
provenance for malicious-category rules, an independent version, a measured
benign baseline -- still applies only to packs, and :attr:`DeclaredRule.origin`
says which kind a rule is so no reader has to guess.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from cordon.core.models import Category, Confidence, Severity

if TYPE_CHECKING:
    from collections.abc import Iterable


@dataclass(frozen=True, slots=True)
class DeclaredRule:
    """One rule a detector can emit, described without running it."""

    id: str
    title: str
    severity: Severity
    confidence: Confidence
    category: Category
    detector: str
    message: str = ""
    remediation: str = ""
    origin: str = "detector"
    """Where the rule is defined.

    ``pack`` for a YAML rule, which carries the loader's guarantees;
    ``detector`` for one declared in Python, which does not. Stated on every
    rule so the difference is visible in `cordon rules list` rather than
    inferred.
    """


class RuleCatalogue:
    """Every rule the installed engine can emit, from packs and detectors alike.

    Built on demand rather than cached: it is used by `cordon rules` and by
    configuration validation, neither of which is on the scanning path.
    """

    @staticmethod
    def from_detectors(detectors: Iterable[Any]) -> tuple[DeclaredRule, ...]:
        """Collect the declarations from every detector that offers them.

        A detector without `declared_rules` contributes nothing rather than
        failing. Third-party detectors are not obliged to declare, and refusing
        to list the built-ins because a plugin does not is the wrong trade.
        """
        out: list[DeclaredRule] = []
        for detector in detectors:
            declare = getattr(detector, "declared_rules", None)
            if declare is None:
                continue
            out.extend(declare())
        return tuple(sorted(out, key=lambda r: r.id))


__all__ = ["DeclaredRule", "RuleCatalogue"]
