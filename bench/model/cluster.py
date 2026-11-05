#!/usr/bin/env python3
"""The campaign split: near-identical packages fall on one side together.

A campaign publishes the same payload under hundreds of names, so a name-hash split can train on
one copy and "detect" its twin. This groups packages whose token sets overlap heavily -- MinHash
signatures, banded locality-sensitive hashing, then union-find over the candidate pairs whose
estimated Jaccard similarity is at least --similarity -- and sends each whole group to train or
held by a hash of its smallest member's id. Writes `campaign_split` and `campaign` into the
manifest.

    docker run --rm --network none -v cordon-model-work:/work -v "$PWD/bench/model:/model" \\
      cordon-model:dev python cluster.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
from scipy import sparse

PERMUTATIONS = 128
BANDS = 32  # 4 rows per band: pairs above ~0.7 similarity almost always share a band
PRIME = (1 << 61) - 1


class Campaigns:
    @staticmethod
    def signatures(tokens: sparse.csr_matrix) -> np.ndarray:
        draw = np.random.default_rng(20261011)
        a = draw.integers(1, PRIME, PERMUTATIONS, dtype=np.uint64)
        b = draw.integers(0, PRIME, PERMUTATIONS, dtype=np.uint64)
        out = np.full((tokens.shape[0], PERMUTATIONS), np.iinfo(np.uint64).max, dtype=np.uint64)
        for row in range(tokens.shape[0]):
            ids = tokens.indices[tokens.indptr[row] : tokens.indptr[row + 1]].astype(np.uint64)
            if len(ids):
                out[row] = ((np.outer(ids, a) + b) % PRIME).min(axis=0)
        return out

    @staticmethod
    def groups(signatures: np.ndarray, similarity: float) -> list[int]:
        parent = list(range(len(signatures)))

        def find(x: int) -> int:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        rows = PERMUTATIONS // BANDS
        empty = np.iinfo(np.uint64).max
        for band in range(BANDS):
            buckets: dict[bytes, list[int]] = defaultdict(list)
            part = signatures[:, band * rows : (band + 1) * rows]
            for i in range(len(part)):
                if part[i, 0] != empty:
                    buckets[part[i].tobytes()].append(i)
            for members in buckets.values():
                if len(members) < 2 or len(members) > 5000:
                    continue
                first = members[0]
                for other in members[1:]:
                    if (
                        find(first) != find(other)
                        and np.mean(signatures[first] == signatures[other]) >= similarity
                    ):
                        parent[find(other)] = find(first)
        return [find(i) for i in range(len(signatures))]

    @staticmethod
    def main() -> int:
        parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
        parser.add_argument("--work", type=Path, default=Path("/work"))
        parser.add_argument("--similarity", type=float, default=0.7)
        args = parser.parse_args()
        manifest = args.work / "manifest.jsonl"
        rows = [
            json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines() if line
        ]
        tokens = sparse.load_npz(args.work / "features" / "tokens.npz").tocsr()
        roots = Campaigns.groups(Campaigns.signatures(tokens), args.similarity)
        members: dict[int, list[int]] = defaultdict(list)
        for i, root in enumerate(roots):
            members[root].append(i)
        for root, group in members.items():
            anchor = min(rows[i]["id"] for i in group)
            side = "train" if hashlib.sha256(anchor.encode()).digest()[0] % 2 == 0 else "held"
            for i in group:
                rows[i]["campaign"] = root
                rows[i]["campaign_split"] = side
        manifest.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
        sizes = sorted((len(g) for g in members.values()), reverse=True)
        print(
            f"{len(rows)} packages in {len(members)} groups; largest {sizes[:10]}; singletons {sizes.count(1)}"
        )
        return 0


if __name__ == "__main__":
    sys.exit(Campaigns.main())
