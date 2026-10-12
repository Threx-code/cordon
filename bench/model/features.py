#!/usr/bin/env python3
"""Package features for every row of the manifest, for training: the product's own extractor.

The features are computed by `cordon_scanner.model.features`, the code the scanner runs on a user's
machine, so the model is trained on exactly what it will be given (checked bit for bit on 1,000
packages when the extractor moved into the package). Samples are read in memory, never extracted to
disk or run; DataDog's archives are opened with their published password.

    docker run --rm --network none -v cordon-bench-data:/data:ro -v cordon-bench-random:/random:ro \\
      -v "$PWD/bench/model:/model" -v cordon-model-work:/work cordon-model:dev python features.py
"""

from __future__ import annotations

import argparse
import json
import sys
from multiprocessing import Pool
from pathlib import Path

import numpy as np
from scipy import sparse

from cordon_scanner.model.features import PACKAGE_DENSE, TOKEN_DIM, PackageArchive, PackageFeatures

DATADOG_PASSWORD = b"infected"


class FeatureJob:
    @staticmethod
    def files(row: dict[str, str]) -> list[tuple[str, bytes]]:
        root = Path("/data") if row["volume"] == "data" else Path("/random")
        try:
            return PackageArchive.members(
                (root / row["path"]).read_bytes(), password=DATADOG_PASSWORD
            )
        except OSError:
            return []

    @staticmethod
    def one(row: dict[str, str]) -> tuple[np.ndarray, list[int], bool]:
        files = FeatureJob.files(row)
        dense, tokens = PackageFeatures.extract(files)
        return np.array(dense, dtype=np.float32), tokens, bool(files)

    @staticmethod
    def main() -> int:
        parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
        parser.add_argument("--manifest", type=Path, default=Path("/work/manifest.jsonl"))
        parser.add_argument("--out", type=Path, default=Path("/work/features"))
        parser.add_argument("--workers", type=int, default=8)
        args = parser.parse_args()
        rows = [
            json.loads(line)
            for line in args.manifest.read_text(encoding="utf-8").splitlines()
            if line
        ]
        with Pool(args.workers) as pool:
            results = pool.map(FeatureJob.one, rows, chunksize=64)
        dense = np.vstack([r[0] for r in results])
        indices: list[int] = []
        indptr = [0]
        for _, tokens, _ in results:
            indices += tokens
            indptr.append(len(indices))
        token_matrix = sparse.csr_matrix(
            (np.ones(len(indices), dtype=np.float32), indices, indptr), shape=(len(rows), TOKEN_DIM)
        )
        args.out.mkdir(parents=True, exist_ok=True)
        np.save(args.out / "dense.npy", dense)
        sparse.save_npz(args.out / "tokens.npz", token_matrix)
        (args.out / "read.json").write_text(json.dumps([r[2] for r in results]), encoding="utf-8")
        (args.out / "dense_names.json").write_text(
            json.dumps(list(PACKAGE_DENSE)), encoding="utf-8"
        )
        print(
            f"{len(rows)} packages; {sum(r[2] for r in results)} read; dense {dense.shape}; tokens nnz {token_matrix.nnz}"
        )
        return 0


if __name__ == "__main__":
    sys.exit(FeatureJob.main())
