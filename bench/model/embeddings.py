#!/usr/bin/env python3
"""Per-package code embeddings from a Model2Vec static model, as extra columns for `train.py`.

Each package's code files (rooted, as the extractor reads them; at most `MAX_FILES` of them, hook
and entry files first, each cut to `MAX_CHARS`) are embedded with a static code model on CPU, and
the package gets the mean and the element-wise maximum of its file vectors: the mean says what the
code is mostly about, the maximum keeps one unusual file -- an injected payload -- from being
averaged away. Written in manifest order to `/work/features/embed.npy`; `train.py --extra embed`
adds them. The model is a local directory pinned in PINNED.json; nothing is downloaded.

    docker run --rm --network none -v cordon-bench-data:/data:ro -v cordon-bench-random:/random:ro \\
      -v cordon-model-work:/work -v cordon-model-weights:/weights:ro -v "$PWD/bench/model:/model:ro" \\
      cordon-model-sem:dev python /model/embeddings.py
"""

from __future__ import annotations

import argparse
import json
import sys
from multiprocessing import Pool
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).parent))
from features import FeatureJob

from cordon_scanner.model.features import CODE, FileFeatures, PackageArchive

MAX_FILES = 200
MAX_CHARS = 8000
_MODEL = None


class Embeddings:
    @staticmethod
    def init(model: str) -> None:
        global _MODEL
        from model2vec import StaticModel

        _MODEL = StaticModel.from_pretrained(model)

    @staticmethod
    def one(row: dict[str, str]) -> np.ndarray:
        assert _MODEL is not None  # noqa: S101 - set by the pool initialiser
        dim = _MODEL.dim
        files = PackageArchive.rooted(FeatureJob.files(row))
        hooks, entries, _ = FileFeatures.hook_targets(files)
        runs = hooks | entries
        code = [(n, b) for n, b in files if n.lower().endswith((*CODE, "setup.py"))]
        code.sort(key=lambda item: (not any(item[0].endswith(t) for t in runs if t), item[0]))
        texts = [
            b[: MAX_CHARS * 2].decode("utf-8", "replace")[:MAX_CHARS] for _, b in code[:MAX_FILES]
        ]
        if not texts:
            return np.zeros(2 * dim, dtype=np.float32)
        vectors = np.asarray(_MODEL.encode(texts), dtype=np.float32)
        return np.concatenate([vectors.mean(axis=0), vectors.max(axis=0)]).astype(np.float32)

    @staticmethod
    def main() -> int:
        parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
        parser.add_argument("--manifest", type=Path, default=Path("/work/manifest.jsonl"))
        parser.add_argument("--model", default="/weights/potion-code-16M-v2")
        parser.add_argument("--out", type=Path, default=Path("/work/features/embed.npy"))
        parser.add_argument("--workers", type=int, default=6)
        args = parser.parse_args()
        rows = [json.loads(x) for x in args.manifest.read_text(encoding="utf-8").splitlines() if x]
        with Pool(args.workers, initializer=Embeddings.init, initargs=(args.model,)) as pool:
            vectors = pool.map(Embeddings.one, rows, chunksize=32)
        matrix = np.vstack(vectors)
        np.save(args.out, matrix)
        print(f"{len(rows)} packages embedded: {matrix.shape}")
        return 0


if __name__ == "__main__":
    sys.exit(Embeddings.main())
