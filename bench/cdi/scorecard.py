"""The scorecard against a frozen baseline and what the loop does when the evidence does not settle it.

Incremental value. A candidate's metrics are shown as the INCREMENTAL value over the baseline the candidate was built against: the recall gain on malware with its 95% bounds (Newcombe's interval for a difference
of two proportions, from the Wilson bounds of each), and the false-block rate on benign units with its upper bound. The baseline is frozen: `Baseline.freeze` stamps its counts with a digest, and a scorecard
against a baseline whose counts no longer match its digest is refused, so a baseline cannot be edited to flatter a candidate.

Thin evidence. The loop never ends in success on thin evidence; every case below ends in `research` or `shadow`, each with its reason:
  unavailable data      a set the decision needs is missing                          -> research
  small n               a set is below the minimum sizes of `claims.py`              -> research
  inconclusive          the gain's interval spans zero                               -> research
  not generalisable     the gain holds in fewer than `MIN_AREAS_WITH_GAIN` areas     -> shadow (it may run beside the scanner, never block)
  clear                 a gain above zero in every area it was measured, enough data -> shadow (a pass earns shadow, never blocking: promotion needs the shadow period and an approval)
There is no `success` outcome here.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any, Final

from bench.cdi.claims import LEGIT_FLOOR, MALWARE_FLOOR

Z: Final = 1.96
MIN_AREAS_WITH_GAIN: Final = 2
OUTCOMES: Final = ("research", "shadow")


class PartialMeasure(ValueError):
    """A scorecard that claims a full-scale measure counts fewer (or more) units than the development and calibration data hold."""


class BaselineEdited(ValueError):
    """A baseline's counts do not match the digest it was frozen with."""


class Proportions:
    @staticmethod
    def wilson(k: int, n: int) -> tuple[float, float]:
        if n == 0:
            return (0.0, 1.0)
        p = k / n
        d = 1 + Z * Z / n
        m = Z * math.sqrt(p * (1 - p) / n + Z * Z / (4 * n * n))
        return ((p + Z * Z / (2 * n) - m) / d, (p + Z * Z / (2 * n) + m) / d)

    @staticmethod
    def difference(k_new: int, n_new: int, k_old: int, n_old: int) -> tuple[float, float, float]:
        """The difference of two proportions (new - old) and its 95% interval (Newcombe's method 10, from the Wilson bounds)."""
        if n_new == 0 or n_old == 0:
            return (0.0, -1.0, 1.0)
        p_new, p_old = k_new / n_new, k_old / n_old
        l_new, u_new = Proportions.wilson(k_new, n_new)
        l_old, u_old = Proportions.wilson(k_old, n_old)
        delta = p_new - p_old
        low = delta - math.sqrt((p_new - l_new) ** 2 + (u_old - p_old) ** 2)
        high = delta + math.sqrt((u_new - p_new) ** 2 + (p_old - l_old) ** 2)
        return (delta, low, high)


class Baseline:
    @staticmethod
    def digest(counts: dict[str, int]) -> str:
        return hashlib.sha256(json.dumps(counts, sort_keys=True).encode("utf-8")).hexdigest()

    @staticmethod
    def freeze(counts: dict[str, int]) -> dict[str, Any]:
        """`counts`: mal_blocked, mal_n, benign_blocked, benign_n of the baseline scanner on the held-out sets."""
        return {"counts": dict(counts), "digest": Baseline.digest(counts)}

    @staticmethod
    def check(baseline: dict[str, Any]) -> None:
        if baseline.get("digest") != Baseline.digest(baseline["counts"]):
            raise BaselineEdited("the baseline's counts do not match the digest it was frozen with")


class Scorecard:
    @staticmethod
    def of(
        baseline: dict[str, Any], candidate: dict[str, int], *, expected_denominator: int | None = None
    ) -> dict[str, Any]:
        """The incremental value of a candidate over the frozen baseline. The card states its denominator (malware plus
        benign units counted). With `expected_denominator`, the full development and calibration count, a card that
        counts any other number of units is refused: a full-scale measure is never a sample."""
        Baseline.check(baseline)
        for blocked, total in (("mal_blocked", "mal_n"), ("benign_blocked", "benign_n")):
            if not 0 <= candidate[blocked] <= candidate[total]:
                raise ValueError(
                    f"{blocked} {candidate[blocked]} is not within {total} {candidate[total]}"
                )
        denominator = candidate["mal_n"] + candidate["benign_n"]
        if expected_denominator is not None and denominator != expected_denominator:
            raise PartialMeasure(
                f"the scorecard counts {denominator} units but the development and calibration data hold "
                f"{expected_denominator}: a full-scale measure is never a sample"
            )
        old = baseline["counts"]
        gain, low, high = Proportions.difference(
            candidate["mal_blocked"], candidate["mal_n"], old["mal_blocked"], old["mal_n"]
        )
        _, benign_upper = Proportions.wilson(candidate["benign_blocked"], candidate["benign_n"])
        return {
            "baseline_digest": baseline["digest"],
            "recall_baseline": old["mal_blocked"] / old["mal_n"] if old["mal_n"] else 0.0,
            "recall_candidate": candidate["mal_blocked"] / candidate["mal_n"]
            if candidate["mal_n"]
            else 0.0,
            "denominator": denominator,
            "full_scale": expected_denominator is not None,
            "mal_n": candidate["mal_n"],
            "benign_n": candidate["benign_n"],
            "recall_gain": gain,
            "recall_gain_low": low,
            "recall_gain_high": high,
            "benign_block_rate": candidate["benign_blocked"] / candidate["benign_n"]
            if candidate["benign_n"]
            else 0.0,
            "benign_block_upper": benign_upper,
            "incremental": low > 0,
        }


class Conclusion:
    @staticmethod
    def of(areas: dict[str, dict[str, Any] | None]) -> dict[str, Any]:
        """Where a candidate ends, from each area's scorecard (`Scorecard.of`), with `None` for an area whose data is unavailable. Never success."""
        reasons: list[str] = []
        missing = sorted(a for a, card in areas.items() if card is None)
        if missing or not areas:
            return Conclusion.end(
                "research", [f"data unavailable for {', '.join(missing) or 'every area'}"]
            )
        # Every area has a scorecard from here on: an area with none ended the question above.
        cards = {a: c for a, c in areas.items() if c is not None}
        small = sorted(a for a, c in cards.items() if Conclusion.too_small(c))
        if small:
            return Conclusion.end("research", [f"small n in {', '.join(small)}"])
        gains = [a for a, c in cards.items() if c["incremental"]]
        spans = sorted(
            a for a, c in cards.items() if c["recall_gain_low"] <= 0 < c["recall_gain_high"]
        )
        if spans and not gains:
            return Conclusion.end(
                "research", [f"inconclusive in {', '.join(spans)}: the gain's interval spans zero"]
            )
        if len(gains) < MIN_AREAS_WITH_GAIN:
            reasons.append(
                f"not generalisable: the gain holds in {len(gains)} of {len(areas)} areas"
            )
            return Conclusion.end("shadow", reasons)
        return Conclusion.end("shadow", ["clear gain; a pass earns shadow, never blocking"])

    @staticmethod
    def too_small(card: dict[str, Any]) -> bool:
        return bool(
            card.get("mal_n", MALWARE_FLOOR) < MALWARE_FLOOR
            or card.get("benign_n", LEGIT_FLOOR) < LEGIT_FLOOR
        )

    @staticmethod
    def end(outcome: str, reasons: list[str]) -> dict[str, Any]:
        if outcome not in OUTCOMES:
            raise ValueError(f"an outcome is research or shadow, never {outcome!r}")
        return {"outcome": outcome, "reasons": reasons}
