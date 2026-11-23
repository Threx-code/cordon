"""What a scanner release will not take from the feed however well it is signed: a set older than the release's floor, or a pack past its expiry.

A scanner in a fresh CI container has no local state, so it cannot know that a signed set it is handed is an old one replayed. The release therefore carries the floor itself: the lowest
feed sequence and the earliest signing date it accepts. The rule-pack index names its `sequence` and the day it was `signed`; a pack's header names the day it `expires`. A set under the
floor, or a pack whose day has passed, is refused with the reason; nothing but the build and the clock is consulted.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, ClassVar, Final

if TYPE_CHECKING:
    from cordon_scanner.rules.pack import RulePack

DAY: Final = re.compile(r"\d{4}-\d{2}-\d{2}")


class FeedFloor:
    MIN_SEQUENCE: ClassVar[int] = 0
    """The lowest feed sequence this release accepts; raised at each release build."""

    MIN_SIGNED: ClassVar[str] = "2026-11-01"
    """The earliest signing day this release accepts (an ISO date)."""

    REQUIRE_EXPIRY: ClassVar[bool] = True
    """Whether a pack without an expiry is refused: every emitted pack names the day it expires."""

    REQUIRE_PACK_SIGNATURES: ClassVar[bool] = True
    """Whether a delivered pack must carry the gate's signature and the pack signer's (`rules/pack_signatures.py`). A release constant, not a field of the index: whoever can change the index must not be able to lower it."""

    @staticmethod
    def today() -> str:
        return datetime.now(UTC).date().isoformat()

    @classmethod
    def set_problem(cls, index: dict[str, Any]) -> str | None:
        """Why a whole delivered set is refused, or None: its sequence or signing day is under this release's floor, or is missing where a floor is set."""
        sequence, signed = index.get("sequence"), index.get("signed")
        if cls.MIN_SEQUENCE > 0 and (isinstance(sequence, bool) or not isinstance(sequence, int)):
            return f"it names no feed sequence and this release's floor is {cls.MIN_SEQUENCE}"
        if (
            isinstance(sequence, int)
            and not isinstance(sequence, bool)
            and sequence < cls.MIN_SEQUENCE
        ):
            return f"its feed sequence {sequence} is under this release's floor {cls.MIN_SEQUENCE}"
        if signed is not None and (not isinstance(signed, str) or not DAY.fullmatch(signed)):
            return "its signing day is not an ISO date"
        if isinstance(signed, str) and signed < cls.MIN_SIGNED:
            return f"it was signed on {signed}, before this release's floor {cls.MIN_SIGNED}"
        return None

    @classmethod
    def pack_problem(cls, pack: RulePack) -> str | None:
        """Why one pack is refused, or None: it has expired, or has no expiry where one is required."""
        if not pack.expires:
            return "it has no expiry" if cls.REQUIRE_EXPIRY else None
        if pack.expires < cls.today():
            return f"it expired on {pack.expires}"
        return None


__all__ = ["FeedFloor"]
