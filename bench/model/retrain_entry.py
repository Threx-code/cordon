"""The one retrain entry: a fixture or real training list in, a model, its metrics and the list's sha256 out, or a refusal.

`RetrainEntry.run` writes the model, `metrics.json` and `training_list.sha256` into the output directory only when the retrained
model passes `RetrainCheck`: nothing the last model blocked and the loop must never lose is let through (additive only), and no
area's line is looser on the established legitimate units. A model that would lower a finding is refused and nothing is written.
"""

from __future__ import annotations

import json
from collections.abc import Collection, Iterable, Mapping
from pathlib import Path
from typing import Any

from bench.cdi.retrain import RetrainCheck
from bench.model.area import Contract


class RetrainRefused(ValueError):
    """The retrained model would lower a finding; the message says what it would lose."""


class RetrainEntry:
    @staticmethod
    def run(
        out: Path,
        *,
        area: str,
        seed: int,
        train_ids: Iterable[str],
        model: Mapping[str, Any],
        metrics: dict[str, Any],
        old_scores: Mapping[str, float],
        old_line: float,
        new_scores: Mapping[str, float],
        new_line: float,
        never_lose: Collection[str],
        scores_by_area: tuple[Mapping[str, Mapping[str, float]], Mapping[str, Mapping[str, float]]]
        | None = None,
        lines_by_area: tuple[Mapping[str, float], Mapping[str, float]] | None = None,
        established: Collection[str] = (),
    ) -> dict[str, Any]:
        report = RetrainCheck.compare(old_scores, old_line, new_scores, new_line, never_lose)
        reasons = [report.refused] if report.refused else []
        if scores_by_area is not None and lines_by_area is not None:
            reasons += RetrainCheck.thresholds(
                scores_by_area[0],
                lines_by_area[0],
                scores_by_area[1],
                lines_by_area[1],
                established,
            )
        if reasons:
            raise RetrainRefused("; ".join(reasons))
        body = Contract.write_contract(
            out,
            area=area,
            seed=seed,
            train_ids=train_ids,
            metrics={**metrics, "flips": report.counts()},
        )
        (out / "model.json").write_text(json.dumps(model, sort_keys=True), encoding="utf-8")
        return body


__all__ = ["RetrainEntry", "RetrainRefused"]
