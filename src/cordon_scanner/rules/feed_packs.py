"""The rule packs the signed feed delivered, loaded as rules (`intel/malware/feed_rules.py` decides
which delivered files are trusted; this loads them): verified packs that fail none of their own
samples, adding to the bundled rules and never replacing one, shadow packs only where asked and
demoted there, and the feed's kill switch applied to delivered rules only.

Rules sit above intel, so the loading lives here and intel never imports the rules layer
(architecture audit F1).
"""

from __future__ import annotations

import logging
from dataclasses import replace
from typing import TYPE_CHECKING, Protocol

from cordon_scanner.foundation.errors import RulePackError
from cordon_scanner.intel.malware.feed_rules import PACK_FILE, FeedRules

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path
    from typing import Any

    from cordon_scanner.rules.pack import RulePack

logger = logging.getLogger("cordon_scanner.intel.malware.feed_rules")


class PackFiles(Protocol):
    """What the delivered packs are read with: the rule loader's file reader."""

    def load_file(self, path: str | Path) -> RulePack: ...


class FeedPacks:
    """The delivered packs a scan loads, from the files `FeedRules` trusts."""

    @classmethod
    def packs(
        cls, loader: PackFiles, bundled_ids: Iterable[str], *, shadow: bool | None = None
    ) -> tuple[RulePack, ...]:
        """The delivered packs this scan loads: verified, not colliding, shadow only when asked."""
        return tuple(pack for _, pack in cls._select(loader, bundled_ids, shadow=shadow))

    @classmethod
    def loaded(
        cls, loader: PackFiles, bundled_ids: Iterable[str], *, shadow: bool | None = None
    ) -> tuple[str, ...]:
        """The candidate ids of the delivered packs a scan here runs, each with a rule still on.

        What the analyser fleet reports beside a verdict, so the Cloud counts a pack as watched on
        a release only where it actually ran (a fleet not yet updated, or a pack refused here,
        must not count towards its record)."""
        return tuple(
            candidate
            for candidate, pack in cls._select(loader, bundled_ids, shadow=shadow)
            if candidate and any(c.rule.enabled for c in pack.rules)
        )

    @classmethod
    def _select(
        cls, loader: PackFiles, bundled_ids: Iterable[str], *, shadow: bool | None
    ) -> list[tuple[str, RulePack]]:
        from cordon_scanner.foundation.models import Category, Confidence, Severity

        shadow = FeedRules.shadow_enabled() if shadow is None else shadow
        taken = set(bundled_ids)
        index = FeedRules.index()
        out: list[tuple[str, RulePack]] = []
        for entry in index.get("packs") or ():
            if not isinstance(entry, dict):
                continue
            name, enforcement = str(entry.get("file", "")), entry.get("enforcement")
            if not PACK_FILE.fullmatch(name) or enforcement not in ("block", "shadow"):
                continue
            if enforcement == "shadow" and not shadow:
                continue
            path = FeedRules.trusted(name)
            if path is None:
                continue
            try:
                pack = loader.load_file(path)
            except (RulePackError, OSError, ValueError) as exc:
                # A bad delivered pack never breaks the scan: it runs on what is bundled.
                logger.warning("feed rule pack %s not loaded: %s", name, exc)
                continue
            from cordon_scanner.rules.tester import RuleTester

            if RuleTester.run(pack):
                # Its own samples fail: the rule would load and match nothing, or the wrong thing.
                logger.warning("feed rule pack %s not loaded: it fails its own samples", name)
                continue
            ids = {rule.id for rule in pack.rules}
            if ids & taken:
                continue  # a delivered pack adds detection; it never replaces a bundled rule
            taken |= ids
            if enforcement == "shadow":
                pack = replace(
                    pack,
                    id=f"shadow:{pack.id}",
                    rules=tuple(
                        replace(
                            compiled,
                            # LOW, where the hardening tier records what decides nothing: INFO is
                            # below the default report threshold, so nobody would see it. Severity
                            # alone is not enough either: a `malicious` rule's category floor lifts
                            # it back to HIGH, so a shadow rule blocked (found end to end). Demoted
                            # in category too, marked by pack, and said in its message.
                            rule=replace(
                                compiled.rule,
                                severity=Severity.LOW,
                                confidence=Confidence.LOW,
                                category=Category.POLICY,
                                rulepack=f"shadow:{compiled.rule.rulepack}",
                                message=f"[shadow: would {compiled.rule.category.value}] "
                                f"{compiled.rule.message}",
                            ),
                        )
                        for compiled in pack.rules
                    ),
                )
            out.append((str(entry.get("candidate_id", ""))[:128], pack))
        disabled = cls.disabled(index, delivered={r.id for _, p in out for r in p.rules})
        if disabled:
            out = [
                (
                    candidate,
                    replace(
                        pack,
                        rules=tuple(
                            replace(c, rule=replace(c.rule, enabled=False))
                            if c.rule.id in disabled
                            else c
                            for c in pack.rules
                        ),
                    ),
                )
                for candidate, pack in out
            ]
        return out

    @staticmethod
    def disabled(index: dict[str, Any], *, delivered: set[str]) -> frozenset[str]:
        """The kill switch, limited to delivered rules: a bundled id in the list is ignored."""
        listed = index.get("disabled_rules") or ()
        return frozenset(str(i) for i in listed if isinstance(i, str) and i in delivered)


__all__ = ["FeedPacks"]
