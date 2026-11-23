"""What a scan could not evaluate of the rules the feed delivered, for its result.

A delivered rule written for a term meaning this scanner does not know is skipped when its pack loads (`FeedPacks`); the scan's own result names it, so a reader of the report or the gate sees
that part of what was asked was not checked.
"""

from __future__ import annotations

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


__all__ = ["FeedGaps"]
