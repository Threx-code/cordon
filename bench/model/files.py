#!/usr/bin/env python3
"""Per-file features for every row of the manifest, for training: the product's own extractor.

A real library with malware injected is hundreds of clean files and one or two that are not, and
package-level features average the bad file away. Each code file is its own row
(`cordon_scanner.model.features.FileFeatures`, the code the scanner runs), at most 96 per package:
every file an install hook or entry point names, then those whose patterns count the most. A
package's file score is its worst file's.

    docker run --rm --network none -v cordon-bench-data:/data:ro -v cordon-bench-random:/random:ro \\
      -v "$PWD/bench/model:/model" -v cordon-model-work:/work cordon-model:dev python files.py
"""

from __future__ import annotations

import argparse
import json
import sys
from multiprocessing import Pool
from pathlib import Path

import numpy as np
from features import FeatureJob

from cordon_scanner.model.features import FILE_DENSE
from cordon_scanner.model.features import FileFeatures as ProductFileFeatures


class FileFeatures:
    @staticmethod
    def one(row: dict[str, str]) -> np.ndarray:
        rows = ProductFileFeatures.rows(FeatureJob.files(row))
        return np.array(rows, dtype=np.float32).reshape(-1, len(FILE_DENSE))

    @staticmethod
    def main() -> int:
        parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
        parser.add_argument("--manifest", type=Path, default=Path("/work/manifest.jsonl"))
        parser.add_argument("--out", type=Path, default=Path("/work/files"))
        parser.add_argument("--workers", type=int, default=6)
        args = parser.parse_args()
        rows = [
            json.loads(line)
            for line in args.manifest.read_text(encoding="utf-8").splitlines()
            if line
        ]
        with Pool(args.workers) as pool:
            results = pool.map(FileFeatures.one, rows, chunksize=32)
        owner = np.concatenate([np.full(len(r), i, dtype=np.int32) for i, r in enumerate(results)])
        matrix = np.vstack(results) if results else np.zeros((0, len(FILE_DENSE)), dtype=np.float32)
        args.out.mkdir(parents=True, exist_ok=True)
        np.save(args.out / "rows.npy", matrix.astype(np.float32))
        np.save(args.out / "owner.npy", owner)
        (args.out / "names.json").write_text(json.dumps(list(FILE_DENSE)), encoding="utf-8")
        print(
            f"{len(rows)} packages; {len(matrix)} file rows; {sum(1 for r in results if not len(r))} with no code file"
        )
        return 0


if __name__ == "__main__":
    sys.exit(FileFeatures.main())
