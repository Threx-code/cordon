"""The nearest labelled releases to one release, by the cosine of their fact vectors.

The judge reads five malicious and five benign releases nearest the one it judges. This module only orders vectors it is
given: it opens no corpus and reads no package, so the caller decides which labelled vectors may be handed to it and where
the search runs. A vector of zeros has no direction and is never near anything.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from cordon_scanner.judge.package_judge import Neighbour


@dataclass(frozen=True, slots=True)
class LabelledVector:
    """One labelled release: an opaque id, its label (`malicious` or `benign`) and its fact vector."""

    release: str
    label: str
    vector: tuple[float, ...]


class NeighbourSearch:
    """Orders labelled vectors by their cosine to a query."""

    PER_LABEL = 5

    @staticmethod
    def cosine(left: Sequence[float], right: Sequence[float]) -> float:
        """The cosine of two vectors of one length; 0.0 when either has no length or they differ in size."""
        if len(left) != len(right):
            return 0.0
        norm = math.sqrt(sum(a * a for a in left)) * math.sqrt(sum(b * b for b in right))
        return sum(a * b for a, b in zip(left, right, strict=True)) / norm if norm else 0.0

    @classmethod
    def nearest(
        cls, query: Sequence[float], labelled: Iterable[LabelledVector]
    ) -> list[LabelledVector]:
        """Up to five of each label, nearest first; a tie goes to the release id so the answer is the same on every run."""
        scored = [(cls.cosine(query, item.vector), item) for item in labelled]
        chosen: list[LabelledVector] = []
        for label in ("malicious", "benign"):
            ranked = sorted(
                (pair for pair in scored if pair[1].label == label and pair[0] > 0.0),
                key=lambda pair: (-pair[0], pair[1].release),
            )
            chosen += [item for _, item in ranked[: cls.PER_LABEL]]
        return chosen

    @classmethod
    def for_bundle(
        cls, query: Sequence[float], labelled: Iterable[LabelledVector]
    ) -> list[Neighbour]:
        """The nearest, as the bundle shows them: the label and the release id, never the vector."""
        return [Neighbour(item.label, item.release) for item in cls.nearest(query, labelled)]
