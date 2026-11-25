"""The time a delivered rule pack may take, measured on the calibration corpus.

Each delivered pack is run over `CalibrationCorpus` with the CPU clock when it loads. The budget is 200 ms for one pack and 500 ms for all delivered packs of a scan, and it is relative to the
machine: the scanner times a fixed reference workload on the same corpus once per process, and a budget is the larger of its fixed figure and ten times that calibration. A pack over its budget
is refused with the reason, and the reason is reported like any other rule the scan did not run. The backend gate calls `PackTime.problem` as the scanner does.
"""

from __future__ import annotations

import re
import time
from typing import TYPE_CHECKING, ClassVar, Final

from cordon_scanner.foundation.once import OneOff
from cordon_scanner.rules.calibration import CalibrationCorpus
from cordon_scanner.rules.pack import RuleOverBudget

if TYPE_CHECKING:
    from cordon_scanner.rules.pack import RulePack

REFERENCE: Final = (
    rb"[a-z]+\(",
    rb"\b(?:al|bo)\w*=",
    rb"(?:cri|dun)+\s*[;,]",
    rb"\d+\.\d+",
    rb'"\s*/[a-z]+',
)


class PackTime:
    PACK_MS: ClassVar[float] = 200.0
    ALL_MS: ClassVar[float] = 500.0
    FACTOR: ClassVar[float] = 10.0

    @staticmethod
    def cpu() -> float:
        """CPU seconds of this thread."""
        return time.thread_time()

    @staticmethod
    @OneOff.cache
    def calibration() -> float:
        """CPU seconds a fixed reference workload takes on the corpus, once per process."""
        files = CalibrationCorpus.files()
        regexes = [re.compile(pattern) for pattern in REFERENCE]
        started = PackTime.cpu()
        for data in files:
            for regex in regexes:
                regex.subn(b"", data)
        return max(PackTime.cpu() - started, 1e-6)

    @classmethod
    def budgets(cls) -> tuple[float, float]:
        """(one pack, all packs) in CPU seconds: the larger of the fixed figure and ten times the calibration."""
        scaled = cls.FACTOR * cls.calibration()
        return max(cls.PACK_MS / 1000, scaled), max(cls.ALL_MS / 1000, scaled)

    @classmethod
    def measure(cls, pack: RulePack) -> float:
        """CPU seconds the pack's text rules take over the corpus; infinite when one is stopped by its own budget."""
        files = CalibrationCorpus.files()
        started = cls.cpu()
        try:
            for compiled in pack.rules:
                match = compiled.match
                if match.regex is None:
                    continue
                for data in files:
                    regex = match.regex_for(data)
                    if regex is not None:
                        for _ in match.matches(regex, data):
                            pass
        except RuleOverBudget:
            return float("inf")
        return cls.cpu() - started

    @classmethod
    def problem(cls, pack: RulePack) -> str | None:
        """Why one pack is over its budget, or None."""
        spent, (limit, _) = cls.measure(pack), cls.budgets()
        if spent > limit:
            return f"its rules took {spent * 1000:.0f} ms on the calibration corpus, over its budget of {limit * 1000:.0f} ms"
        return None

    @classmethod
    def total_problem(cls, spent: float) -> str | None:
        """Why the delivered packs together are over the per-scan budget, or None."""
        limit = cls.budgets()[1]
        if spent > limit:
            return f"with the packs before it the rules took {spent * 1000:.0f} ms on the calibration corpus, over the {limit * 1000:.0f} ms all packs may take"
        return None


__all__ = ["PackTime"]
