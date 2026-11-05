"""Scoring requests against a loaded bundle (`cordon.model/v1`).

A request carries, per package, what `cordon_scanner.model.features` computed on the client: the
package's dense features, its token buckets, and up to 96 per-file rows. Nothing else -- no names
needed, no source. Every value is checked before it reaches the model: lengths, counts, finiteness
and ranges, so a malformed or hostile request is refused with a reason rather than scored.
"""

from __future__ import annotations

import math
import threading
from dataclasses import dataclass
from typing import Any, Final

import lightgbm as lgb
import numpy as np
from scipy import sparse

from cordon_model_server.bundle import Bundle
from cordon_scanner.model.features import FILE_DENSE, PACKAGE_DENSE, PER_PACKAGE_FILES, TOKEN_DIM

MAX_PACKAGES: Final = 100
MAX_TOKENS: Final = TOKEN_DIM  # every bucket at most once: the client sends what extraction found
MAX_REF: Final = 200


class RequestError(ValueError):
    """A request that is not scored, with the reason the client is told."""


@dataclass(frozen=True, slots=True)
class PackageInput:
    ref: str
    dense: list[float]
    tokens: list[int]
    files: list[list[float]]


class Scorer:
    def __init__(self, bundle: Bundle) -> None:
        self.bundle = bundle
        self.package_model = lgb.Booster(model_file=str(bundle.root / "package.txt"))
        file_path = bundle.root / "file.txt"
        self.file_model = (
            lgb.Booster(model_file=str(file_path)) if bundle.file_threshold is not None else None
        )
        self.columns = np.array(bundle.columns, dtype=np.int64)
        # LightGBM boosters are not documented as thread-safe for predict: one at a time.
        self.lock = threading.Lock()

    @staticmethod
    def _numbers(value: Any, width: int, what: str) -> list[float]:
        if not isinstance(value, list) or len(value) != width:
            raise RequestError(f"{what} must be a list of {width} numbers")
        out: list[float] = []
        for item in value:
            if (
                isinstance(item, bool)
                or not isinstance(item, int | float)
                or not math.isfinite(item)
            ):
                raise RequestError(f"{what} must hold finite numbers")
            out.append(float(item))
        return out

    @staticmethod
    def parse(body: Any) -> list[PackageInput]:
        if not isinstance(body, dict) or body.get("schema") != "cordon.model/v1":
            raise RequestError(
                'the request must be a cordon.model/v1 object ({"schema": "cordon.model/v1", ...})'
            )
        packages = body.get("packages")
        if not isinstance(packages, list) or not 1 <= len(packages) <= MAX_PACKAGES:
            raise RequestError(f"packages must be a list of 1 to {MAX_PACKAGES}")
        parsed: list[PackageInput] = []
        for entry in packages:
            if not isinstance(entry, dict):
                raise RequestError("each package is an object")
            ref = entry.get("ref")
            if not isinstance(ref, str) or not 0 < len(ref) <= MAX_REF:
                raise RequestError(f"ref must be a string of 1 to {MAX_REF} characters")
            dense = Scorer._numbers(entry.get("dense"), len(PACKAGE_DENSE), "dense")
            tokens = entry.get("tokens", [])
            if (
                not isinstance(tokens, list)
                or len(tokens) > MAX_TOKENS
                or not all(
                    isinstance(t, int) and not isinstance(t, bool) and 0 <= t < TOKEN_DIM
                    for t in tokens
                )
            ):
                raise RequestError(
                    f"tokens must be at most {MAX_TOKENS} integers in [0, {TOKEN_DIM})"
                )
            files = entry.get("files", [])
            if not isinstance(files, list) or len(files) > PER_PACKAGE_FILES:
                raise RequestError(f"files must be a list of at most {PER_PACKAGE_FILES} rows")
            rows = [Scorer._numbers(r, len(FILE_DENSE), "a file row") for r in files]
            parsed.append(PackageInput(ref, dense, sorted(set(tokens)), rows))
        return parsed

    def score(self, packages: list[PackageInput]) -> list[dict[str, Any]]:
        width = len(PACKAGE_DENSE) + TOKEN_DIM
        data: list[float] = []
        indices: list[int] = []
        indptr = [0]
        for p in packages:
            for i, v in enumerate(p.dense):
                if v != 0.0:
                    indices.append(i)
                    data.append(v)
            for t in p.tokens:
                indices.append(len(PACKAGE_DENSE) + t)
                data.append(1.0)
            indptr.append(len(indices))
        full = sparse.csr_matrix(
            (np.array(data, dtype=np.float32), np.array(indices, dtype=np.int64), np.array(indptr)),
            shape=(len(packages), width),
        )
        matrix = full[:, self.columns]
        with self.lock:
            package_scores = self.package_model.predict(matrix)
            file_scores: list[float | None] = []
            for p in packages:
                if self.file_model is None or not p.files:
                    file_scores.append(None if self.file_model is None else 0.0)
                    continue
                file_scores.append(
                    float(np.max(self.file_model.predict(np.array(p.files, dtype=np.float32))))
                )
        results = []
        for p, ps, fs in zip(packages, package_scores, file_scores, strict=True):
            by_package = float(ps) > self.bundle.package_threshold
            by_file = (
                fs is not None
                and self.bundle.file_threshold is not None
                and fs > self.bundle.file_threshold
            )
            results.append(
                {
                    "ref": p.ref,
                    "verdict": "malicious" if by_package or by_file else "benign",
                    "package_score": round(float(ps), 6),
                    "file_score": None if fs is None else round(fs, 6),
                    "reasons": [
                        r for r, hit in (("package", by_package), ("file", by_file)) if hit
                    ],
                }
            )
        return results
