"""What a learned rule says about where it came from: how many families it was learned from, how often legitimate packages fire it with the interval that rate lies in, and the batch it was learned in.

A finding's explanation shows these (`PackageRules.learned_basis`). A block that is not of this form is a broken pack and is refused when it is read.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar

from cordon_scanner.foundation.errors import RulePackError
from cordon_scanner.foundation.models import Confidence


class LearnedBlock:
    KEYS: ClassVar[frozenset[str]] = frozenset({"families", "legit_rate", "interval", "batch"})
    OPTIONAL: ClassVar[frozenset[str]] = frozenset({"n"})
    """`n`: how many established legitimate units the rate was measured on."""
    BATCH: ClassVar[re.Pattern[str]] = re.compile(r"[A-Za-z0-9._:-]{1,64}")

    @classmethod
    def check(cls, raw: Any, *, where: str) -> None:
        """Nothing for a rule with no block; `RulePackError` for a block that is not exactly the four fields, in range."""
        if raw is None:
            return
        if not isinstance(raw, dict) or not cls.KEYS <= set(raw) <= cls.KEYS | cls.OPTIONAL:
            raise RulePackError(
                f"{where}: `learned` must hold exactly families, legit_rate, interval and batch"
            )
        if not cls.well_formed(raw) or not cls.count_ok(raw.get("n", 1)):
            raise RulePackError(
                f"{where}: `learned` is malformed (families a count, legit_rate and its interval within 0 and 1 with the rate inside it, batch a short name)"
            )

    @classmethod
    def well_formed(cls, raw: dict[str, Any]) -> bool:
        families, rate, interval, batch = (
            raw["families"],
            raw["legit_rate"],
            raw["interval"],
            raw["batch"],
        )
        if isinstance(families, bool) or not isinstance(families, int) or families < 1:
            return False
        if not cls.number(rate) or not isinstance(interval, list) or len(interval) != 2:
            return False
        if not all(cls.number(item) for item in interval):
            return False
        return (
            0 <= interval[0] <= rate <= interval[1] <= 1
            and isinstance(batch, str)
            and cls.BATCH.fullmatch(batch) is not None
        )

    @staticmethod
    def count_ok(value: Any) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and value >= 1

    @classmethod
    def confidence(cls, raw: dict[str, Any]) -> Confidence:
        """The confidence the measured rate earns: 1 minus the interval's upper bound, HIGH from 0.99, MEDIUM from 0.95, else LOW. Never CONFIRMED."""
        trust = 1 - raw["interval"][1]
        return (
            Confidence.HIGH
            if trust >= 0.99
            else Confidence.MEDIUM
            if trust >= 0.95
            else Confidence.LOW
        )

    @staticmethod
    def number(value: Any) -> bool:
        return isinstance(value, (int, float)) and not isinstance(value, bool)


__all__ = ["LearnedBlock"]
