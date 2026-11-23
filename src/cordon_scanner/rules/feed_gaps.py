"""What a scan could not evaluate of the rules the feed delivered, for its result.

A delivered rule written for a term meaning this scanner does not know is skipped when its pack loads (`FeedPacks`); the scan's own result names it, so a reader of the report or the gate sees
that part of what was asked was not checked.
"""

from __future__ import annotations

from typing import Any

from cordon_scanner.intel.malware.feed_rules import FeedRules
from cordon_scanner.rules.feed_packs import FeedPacks
from cordon_scanner.rules.loader import RuleLoader


class FeedGaps:
    @staticmethod
    def demoted() -> dict[str, str]:
        """The delivered rules a default scan here ran as warnings, by rule id with the reason; empty when none was."""
        loader = RuleLoader()
        delivered = {pack.id for pack in FeedPacks.packs(loader, set())}
        bundled = {
            compiled.rule.id
            for pack in RuleLoader.load_builtin()
            if pack.id not in delivered
            for compiled in pack.rules
        }
        return dict(FeedPacks.demoted(loader, bundled))

    @staticmethod
    def skipped() -> dict[str, str]:
        """The delivered rules a default scan here skipped, by rule id with the reason; empty when none was."""
        loader = RuleLoader()
        delivered = {pack.id for pack in FeedPacks.packs(loader, set())}
        bundled = {
            compiled.rule.id
            for pack in RuleLoader.load_builtin()
            if pack.id not in delivered
            for compiled in pack.rules
        }
        return dict(FeedPacks.skipped(loader, bundled))

    @staticmethod
    def feed() -> dict[str, Any]:
        """The feed this scan ran on: the serial of the delivered rule-pack set (`"none"` with no feed) and the version of each delivered pack."""
        loader = RuleLoader()
        packs = FeedPacks.packs(loader, set())
        sequence = FeedRules.index().get("sequence") if packs else None
        serial = (
            str(sequence)
            if isinstance(sequence, int) and not isinstance(sequence, bool)
            else "none"
        )
        return {
            "serial": serial,
            "packs": {pack.id: pack.version for pack in sorted(packs, key=lambda p: p.id)},
        }


__all__ = ["FeedGaps"]
