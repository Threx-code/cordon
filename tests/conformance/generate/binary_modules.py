"""The malformed binary-module corpus, derived from the benign reference executables.

The benign fixtures under ``tests/unit/data/rule_reference/modules`` are real, redistributable
executables (their licences and origins are in that directory's README). ``Corpus.mutate`` derives a
malformed set from them deterministically -- truncations at a spread of structure-boundary fractions,
byte flips in the header region, field overwrites with extreme values, and a scatter of random bytes
-- so the exact same bytes regenerate anywhere from the committed fixtures, with no corpus to ship. The
seed is pinned; a per-file digest is recorded so the replay test fails loudly if the mutator drifts.

The replay (``tests/unit/detect/binary/test_rule_malformed_replay.py``) imports ``Corpus.mutate`` and
holds Cordon's readers to the recorded values in ``malformed.json``. Recording those values is a
maintainer's measurement step that needs the reference installed, and so is not part of Cordon:
``scripts/reference/record_binary_modules.py``.
"""

from __future__ import annotations

import random
from typing import ClassVar


class Corpus:
    """The deterministic malformed set derived from the benign reference executables."""

    #: pinned so the derived bytes are identical on every machine; bump with the scheme (and re-record)
    SEED: ClassVar[str] = "cordon-binary-malformed-v1"
    #: the benign fixtures the malformed set derives from (the rest of the directory is reference data)
    FIXTURES: ClassVar[tuple[str, ...]] = (
        "amazon-lambda-core.dll",
        "cpython-wmi.pyd",
        "libffi-raw_api.o",
        "system-runtime-compilerservices-unsafe.dll",
    )
    _TRUNCATIONS: ClassVar[tuple[float, ...]] = (0.001, 0.01, 0.05, 0.25, 0.5, 0.9)
    _EXTREMES: ClassVar[tuple[bytes, ...]] = (
        b"\xff\xff\xff\xff",
        b"\x00\x00\x00\x00",
        b"\xff\xff\xff\x7f",
        b"\x00\x00\x00\x80",
    )

    @staticmethod
    def mutate(fixtures: dict[str, bytes]) -> dict[str, bytes]:
        """The malformed set derived from ``{name: bytes}``, deterministically. Each fixture is seeded by
        its own name, so the result does not depend on iteration order."""
        out: dict[str, bytes] = {}
        for name in sorted(fixtures):
            data = fixtures[name]
            n = len(data)
            head = min(n, 4096)
            rng = random.Random(f"{Corpus.SEED}:{name}")  # noqa: S311 - a reproducible corpus, not security
            for frac in Corpus._TRUNCATIONS:
                out[f"{name}~trunc{frac}"] = data[: max(64, int(n * frac))]
            for k in range(6):
                flipped = bytearray(data)
                for _ in range(8):
                    flipped[rng.randrange(head)] ^= 1 << rng.randrange(8)
                out[f"{name}~flip{k}"] = bytes(flipped)
            for k in range(6):
                overwritten = bytearray(data)
                at = rng.randrange(max(1, head - 4)) & ~3
                overwritten[at : at + 4] = rng.choice(Corpus._EXTREMES)
                out[f"{name}~field{k}"] = bytes(overwritten)
            if n > 4096:
                scattered = bytearray(data)
                for _ in range(64):
                    scattered[rng.randrange(n)] = rng.randrange(256)
                out[f"{name}~scatter"] = bytes(scattered)
        return out
