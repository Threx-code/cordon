"""A pickle is read to its end whatever its size, and the walk's memory is a small multiple of the
pickle's bytes (review 98, D): the memo keeps 8 bytes an entry, the offset of a memoised string,
never the text, so a dictionary cache of millions of opcodes costs about a byte per pickle byte.
"""

from __future__ import annotations

import gc
import pickle
import tracemalloc

import pytest

from cordon_scanner.analysis.formats import pickles

pytestmark = pytest.mark.perf


class PickleMemory:
    @staticmethod
    def cache(words: int) -> bytes:
        """A pronunciation-dictionary cache: a dict of words to lists of phoneme strings, every
        string memoised by the protocol."""
        return pickle.dumps(
            {
                f"word {n}": [f"PH{n % 40} AH0", f"PH{(n * 7) % 40} T", "AH0 B"]
                for n in range(words)
            },
            protocol=4,
        )

    @staticmethod
    def peak(data: bytes) -> int:
        """Bytes the walk allocates at most, the pickle's own bytes excluded."""
        gc.collect()
        tracemalloc.start()
        try:
            report = pickles.PickleReader.read(data)
            _held, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert report.pickles == 1 and not report.partial, report
        return peak


class TestTheWalkHoldsNoText:
    def test_the_walk_costs_a_few_bytes_per_pickle_byte_at_any_size(self) -> None:
        small, large = PickleMemory.cache(50_000), PickleMemory.cache(200_000)
        assert len(large) > 4 * 10**6
        peak_small, peak_large = PickleMemory.peak(small), PickleMemory.peak(large)
        assert peak_large <= 3.0 * len(large), (
            f"{peak_large / len(large):.1f} bytes per pickle byte"
        )
        # And linear: four times the pickle, at most five times the memory.
        assert peak_large <= 5 * peak_small, (
            f"{peak_large / 1e6:.1f} MB at 4x, {peak_small / 1e6:.1f} MB at 1x"
        )

    def test_the_memo_holds_offsets_not_text(self) -> None:
        report = pickles.PickleReader.read(PickleMemory.cache(10_000))
        # Four strings and a list per word, a dictionary around them: about five memo entries a
        # word, at 8 bytes each, however long the words.
        assert 0 < report.memo_bytes <= 8 * (5 * 10_000 + 2)
