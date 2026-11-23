"""A fixed corpus of invented packages for the prepush performance gate, and the two measures taken over it.

The corpus is generated from a fixed seed: 60 small packages of JavaScript, Python and JSON files, a few of them with the shapes
that cost the scanner most (long minified lines, deep nesting, many string literals). Its content hash is part of the gate, so
a change to the generator is a change to the corpus and is noticed. Time is measured as a ratio to a fixed pure-Python
workload run on the same machine, so the same gate holds on a slow laptop and a fast one.
"""

from __future__ import annotations

import hashlib
import random
import time
import tracemalloc
from pathlib import Path
from typing import Any

from cordon_scanner import Scanner
from cordon_scanner.foundation.config.settings import Config


class PerfCorpus:
    PACKAGES = 60
    SEED = 20261123

    @classmethod
    def files(cls) -> dict[str, str]:
        rng = random.Random(cls.SEED)  # noqa: S311 -- invented fixture text, not a secret
        out: dict[str, str] = {}
        for n in range(cls.PACKAGES):
            root = f"pkg{n:03d}"
            out[f"{root}/package.json"] = (
                f'{{"name":"inv-{n}","version":"1.0.{n}","main":"index.js"}}\n'
            )
            words = [f"v{rng.randrange(10**6)}" for _ in range(30)]
            out[f"{root}/index.js"] = (
                "".join(f"const {w} = require('./lib/{w}');\n" for w in words[:10])
                + "module.exports = {};\n"
            )
            out[f"{root}/lib/util.js"] = "".join(
                f"function f{i}(a, b) {{ return a + b * {i}; }}\n"
                for i in range(rng.randrange(20, 80))
            )
            if n % 6 == 0:
                out[f"{root}/lib/min.js"] = (
                    ";".join(
                        f"var {w}=function(x){{return x+{i}}}" for i, w in enumerate(words * 40)
                    )
                    + ";\n"
                )
            if n % 10 == 0:
                depth = rng.randrange(8, 14)
                out[f"{root}/lib/nest.js"] = ("`a${" * depth + "x" + "}b`" * depth + ";\n") * 40
            if n % 4 == 0:
                out[f"{root}/tool.py"] = "".join(
                    f"def g{i}(x):\n    return [y for y in range(x) if y % {i + 2}]\n\n"
                    for i in range(rng.randrange(15, 60))
                )
            out[f"{root}/data.json"] = (
                "[" + ",".join(f'{{"k{i}":"{w}"}}' for i, w in enumerate(words)) + "]\n"
            )
        return out

    @classmethod
    def digest(cls) -> str:
        sha = hashlib.sha256()
        for name, text in sorted(cls.files().items()):
            sha.update(name.encode() + b"\0" + text.encode() + b"\0")
        return sha.hexdigest()

    @classmethod
    def write(cls, root: Path) -> list[Path]:
        packages: dict[str, Path] = {}
        for name, text in cls.files().items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            packages[name.split("/")[0]] = root / name.split("/")[0]
        return [packages[k] for k in sorted(packages)]

    @staticmethod
    def calibration() -> float:
        """Seconds a fixed pure-Python workload takes here, the unit the scan times are read in."""
        best = float("inf")
        for _ in range(5):
            began = time.perf_counter()
            total = 0
            for i in range(400_000):
                total += (i * i) % 7
            best = min(best, time.perf_counter() - began)
        return best

    @classmethod
    def measure(cls, root: Path) -> dict[str, Any]:
        """`p99_ratio` (p99 package scan time over the calibration) and `peak_kb` (traced peak memory) of scanning every package."""
        scanner = Scanner(Config.default().with_overrides(use_cache=False, offline=True))
        unit = cls.calibration()
        packages = cls.write(root)
        scanner.scan(packages[0])  # warm: imports and compiled rules are not the corpus's cost
        times = []
        tracemalloc.start()
        for package in packages:
            best = float("inf")
            for _ in range(3):
                began = time.perf_counter()
                scanner.scan(package)
                best = min(best, time.perf_counter() - began)
            times.append(best)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        times.sort()
        p99 = times[min(len(times) - 1, int(len(times) * 0.99))]
        return {"p99_ratio": p99 / unit, "peak_kb": peak // 1024, "packages": len(packages)}
