"""Keep improving: the scheduled retrain of a model, and what each run leaves behind.

A retrain runs on a cadence and whenever a labelled batch arrives, and each one ends the same way:

    list      the training list is the standing list plus the live captures that two distinct reviewers labelled; a capture with fewer
              readers is left out and counted, and one already held out of training (a sealed, held-out or fresh unit) is refused whole
    model     the model is trained only through the one entry point (`bench/model/train.py`), whose contract gives the list's hash
    report    the model's acceptance report (`ModelAcceptance`): a model that does not pass it is not put into shadow
    shadow    a model that passes is recorded as a shadow run: it scores beside the scanner and blocks nothing; promotion is a
              separate decision
    drift     the share of packages near the model's line, per area, is added to the drift series

Nothing here trains by itself: the trainer, the acceptance and the shadow scoring are given to it, so each can be a fixture or the real
thing. It keeps counts, hashes and names of artefacts, never a unit."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from typing import Any, Final

from bench.cdi.drift import DriftSeries
from bench.cdi.model_acceptance import ModelAcceptance

MIN_REVIEWERS: Final = 2


class RetrainRefused(ValueError):
    """The list or the run breaks a rule: a held-out unit in training, or a model with no list hash."""


class TrainingList:
    @staticmethod
    def build(
        standing: Iterable[str], captures: Iterable[Mapping[str, Any]], held_out: frozenset[str] = frozenset()
    ) -> dict[str, Any]:
        """The standing ids plus each capture labelled by two distinct reviewers. A capture is `{"id", "reviewers": [...]}`."""
        ids = set(standing)
        if ids & held_out:
            raise RetrainRefused("the standing list holds a unit that is held out of training")
        joined = left_out = 0
        for capture in captures:
            if capture["id"] in held_out:
                raise RetrainRefused("a live capture is a unit that is held out of training")
            if len(set(capture.get("reviewers", ()))) >= MIN_REVIEWERS:
                ids.add(capture["id"])
                joined += 1
            else:
                left_out += 1
        return {"ids": sorted(ids), "captures_joined": joined, "captures_left_out": left_out}


class Cadence:
    @staticmethod
    def due(now: float, last_run: float | None, every_seconds: float, new_batch: bool) -> str | None:
        """Why a retrain runs now (`batch` or `cadence`), or None when it does not."""
        if new_batch:
            return "batch"
        if last_run is None or now - last_run >= every_seconds:
            return "cadence"
        return None


class Retrain:
    @staticmethod
    def run(
        *,
        reason: str,
        training: Mapping[str, Any],
        train: Callable[[list[str]], Mapping[str, Any]],
        evidence: Callable[[Mapping[str, Any]], Mapping[str, Any]],
        shadow: Callable[[Mapping[str, Any]], Mapping[str, Any]],
        drift: DriftSeries,
        window: str,
        scores_by_area: Mapping[str, Iterable[float]],
    ) -> dict[str, Any]:
        """One retrain. `train(ids)` returns the model's description (`model`, `training_list_sha`); `evidence(model)` the numbers
        `ModelAcceptance` reads; `shadow(model)` records the shadow run."""
        model = dict(train(list(training["ids"])))
        if not model.get("model") or not str(model.get("training_list_sha", "")).startswith("sha256:"):
            raise RetrainRefused("the trainer gave no model or no training list hash: it did not run through the entry point")
        report = ModelAcceptance.report(evidence(model))
        shadow_run: dict[str, Any] | None = None
        if report["accepted"]:
            shadow_run = dict(shadow(model))
            if shadow_run.get("enforcement") != "shadow":
                raise RetrainRefused("a retrained model starts in shadow and blocks nothing")
        points = drift.add(window, scores_by_area)
        return {
            "reason": reason,
            "model": model,
            "captures_joined": training["captures_joined"],
            "report": report,
            "shadow": shadow_run,
            "outcome": "shadow" if shadow_run else "research",
            "drift": points,
        }
