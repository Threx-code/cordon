"""The threat relationship graph (SI-C1): artefacts, releases, files, fragments, campaign and infrastructure indicators, weighted by evidence. Common code never implicates alone.

Nodes are `kind:id` strings (`artifact:`, `release:`, `file:`, `fragment:`, `campaign:`, `infra:`). An edge joins an artefact to a thing it has: a release, a file, a code fragment, a campaign label, an
infrastructure indicator (a host, a wallet, a key). Each edge carries a weight by what it is evidence of:

    infra      1.0   the same host, wallet or key: the strongest link
    campaign   1.0   the same labelled campaign
    file       0.6   a byte-identical file                  (scaled down by how common the file is, below)
    fragment   0.4   a shared code fragment                 (scaled down by how common the fragment is)
    release    0.2   the same package's other release

Commonness: a file or fragment seen in at least `COMMON_AT` of the benign units is COMMON CODE (a licence header, a vendored helper, a boilerplate setup file) and its weight is 0; a less common one is
scaled by `1 - share / COMMON_AT`. So shared common code adds no implication, and an artefact is implicated by a seed only when the evidence of at least `MIN_KINDS` different kinds is strong enough
together (`THRESHOLD`) or one kind alone is as strong as infra or a campaign. Evidence is counted once per kind (the strongest edge of each kind), so a hundred shared fragments are not a hundred votes.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Final

WEIGHTS: Final = {"infra": 1.0, "campaign": 1.0, "file": 0.6, "fragment": 0.4, "release": 0.2}
COMMON_AT: Final = 0.05
THRESHOLD: Final = 1.0
MIN_KINDS: Final = 2


class ThreatGraph:
    def __init__(self, benign_share: dict[str, float] | None = None) -> None:
        #: node -> the share of benign units it appears in (files and fragments only; the rest are 0).
        self.benign_share = dict(benign_share or {})
        self.having: dict[str, set[str]] = defaultdict(set)  # artefact -> the nodes it has
        self.had_by: dict[str, set[str]] = defaultdict(set)  # node -> the artefacts that have it

    def add(self, artifact: str, node: str) -> None:
        """The artefact has this node (`kind:id`)."""
        kind, separator, _ = node.partition(":")
        if not separator or kind not in WEIGHTS:
            raise ValueError(f"node {node!r} is not one of {sorted(WEIGHTS)}")
        self.having[artifact].add(node)
        self.had_by[node].add(artifact)

    def weight(self, node: str) -> float:
        """What sharing this node is worth: its kind's weight, 0 for common code, scaled down by how common it is."""
        kind = node.partition(":")[0]
        base = WEIGHTS[kind]
        if kind not in ("file", "fragment"):
            return base
        share = self.benign_share.get(node, 0.0)
        return 0.0 if share >= COMMON_AT else base * (1 - share / COMMON_AT)

    def evidence(self, seed: str, other: str) -> dict[str, float]:
        """The strongest shared edge of each kind between two artefacts (kinds with no weight left are dropped)."""
        best: dict[str, float] = {}
        for node in self.having[seed] & self.having[other]:
            weight = self.weight(node)
            if weight > 0:
                kind = node.partition(":")[0]
                best[kind] = max(best.get(kind, 0.0), weight)
        return best

    def score(self, seed: str, other: str) -> float:
        return sum(self.evidence(seed, other).values())

    def implicated(self, seed: str) -> dict[str, float]:
        """The artefacts a seed implicates, with their scores: at least `THRESHOLD` together from at least `MIN_KINDS` kinds, or a single kind as strong as `THRESHOLD`."""
        out: dict[str, float] = {}
        candidates = {a for node in self.having[seed] for a in self.had_by[node]} - {seed}
        for other in sorted(candidates):
            evidence = self.evidence(seed, other)
            total = sum(evidence.values())
            if total >= THRESHOLD and (
                len(evidence) >= MIN_KINDS or max(evidence.values()) >= THRESHOLD
            ):
                out[other] = total
        return out
