"""detect.binary.modules.builtin: a region's byte tally is taken in one pass and kept for the file,
and so is each hash of a region, the last few hundred regions kept. On the 14 large files 256
passes a tally took 7.70 s, and 668 hashes of a few regions 5.8 s (review 6y). The answers are the
old algorithm's, bit for bit; the memory kept is bounded however many regions a rule asks for."""

from __future__ import annotations

import hashlib
import math
import random
import sys
import tracemalloc

import pytest

from cordon_scanner.detect.binary.modules.builtin import ByteStats, HashModule, MathModule


class Old:
    """The tally as it was taken: one `count` a byte value."""

    @staticmethod
    def tally(run: bytes) -> list[int]:
        return [run.count(v) for v in range(256)] if run else [0] * 256

    @staticmethod
    def entropy(run: bytes) -> float:
        bits = 0.0
        for n in Old.tally(run):
            if n:
                share = n / len(run)
                bits -= share * math.log2(share)
        return bits


class Calls:
    """C calls of one function made while `run()` ran, seen by the profiler (a wrapper on a C
    method of `bytes` sees nothing: the module calls it on plain slices)."""

    @staticmethod
    def count(name: str, run) -> int:
        seen = [0]

        def profile(frame, event, arg) -> None:
            if event == "c_call" and getattr(arg, "__qualname__", "") == name:
                seen[0] += 1

        sys.setprofile(profile)
        try:
            run()
        finally:
            sys.setprofile(None)
        return seen[0]


class TestRegionTallies:
    DATA = bytes(random.Random(6).randrange(256) for _ in range(1 << 16))  # noqa: S311 -- a fixture, not key material

    def test_fifty_asks_of_one_region_take_no_256_pass_tally(self) -> None:
        entropy = MathModule(self.DATA).values()["entropy"][0]
        passes = Calls.count("bytes.count", lambda: [entropy(1024, 4096) for _ in range(50)])
        assert passes == 0  # it was 256 a region, every ask: 12,800

    def test_the_tally_is_worked_out_once_a_region(self, monkeypatch) -> None:
        taken = []
        real = ByteStats.tally_of
        monkeypatch.setattr(
            ByteStats, "tally_of", staticmethod(lambda r: taken.append(1) or real(r))
        )
        values = MathModule(self.DATA).values()
        for _ in range(50):
            values["entropy"][0](1024, 4096)
            values["mean"][0](1024, 4096)
            values["mode"][0](1024, 4096)
        assert len(taken) == 1

    def test_answers_are_the_old_algorithm_s_bit_for_bit(self) -> None:
        values = MathModule(self.DATA).values()
        rng = random.Random(7)  # noqa: S311 -- a fixture, not key material
        for _ in range(200):
            offset, length = rng.randrange(len(self.DATA)), rng.randrange(1, 9000)
            run = self.DATA[offset : offset + length]
            old = ByteStats(run, tuple(Old.tally(run)))
            assert values["entropy"][0](offset, length) == Old.entropy(run)
            assert values["mean"][0](offset, length) == old.mean()
            assert values["deviation"][0](offset, length, 127.5) == old.deviation(127.5)
            assert values["mode"][0](offset, length) == old.most_common()
            # read in order, from the bytes, as before
            assert values["serial_correlation"][0](offset, length) == old.serial_correlation()
            assert values["monte_carlo_pi"][0](offset, length) == old.pi_error()

    def test_a_region_past_the_end_is_the_region_it_reads(self) -> None:
        module = MathModule(self.DATA)
        entropy = module.values()["entropy"][0]
        tail = len(self.DATA) - 100
        assert entropy(tail, 10_000) == entropy(tail, 100) == Old.entropy(self.DATA[tail:])
        assert len(module.tallies) == 1  # one span, however it was asked

    def test_a_string_is_not_a_region_and_is_not_kept(self) -> None:
        module = MathModule(self.DATA)
        assert module.values()["entropy"][1](b"abcabc") == Old.entropy(b"abcabc")
        assert len(module.tallies) == 0

    def test_ten_thousand_regions_keep_at_most_the_bound(self) -> None:
        data = bytes(random.Random(8).randrange(256) for _ in range(10 << 20))  # noqa: S311 -- a fixture, not key material
        module = MathModule(data)
        entropy = module.values()["entropy"][0]
        tracemalloc.start()
        try:
            base, _ = tracemalloc.get_traced_memory()
            for i in range(10_000):
                entropy(i * 1024, 1024)  # every block once: a common rule's loop
            grown, _ = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert len(module.tallies) <= 256
        assert grown - base < 2 << 20  # 256 tallies, not 10,000


class TestRegionHashes:
    DATA = bytes(range(256)) * 512

    def test_six_hundred_asks_of_one_region_hash_it_once(self, monkeypatch) -> None:
        made = []
        real = hashlib.new
        monkeypatch.setattr(
            hashlib, "new", lambda name, data=b"": made.append(name) or real(name, data)
        )
        md5 = HashModule(self.DATA).values()["md5"][0]
        answers = {md5(0, len(self.DATA)) for _ in range(668)}
        assert answers == {hashlib.md5(self.DATA).hexdigest().encode()}  # noqa: S324 -- the expected digest of a fixture, not a security use
        assert len(made) == 1  # it was 668

    @pytest.mark.parametrize("name", ["md5", "sha1", "sha256", "crc32", "checksum32"])
    def test_each_function_keeps_its_own_answer(self, name: str) -> None:
        module = HashModule(self.DATA)
        values = module.values()
        first = {
            n: values[n][0](16, 4096) for n in ("md5", "sha1", "sha256", "crc32", "checksum32")
        }
        assert values[name][0](16, 4096) == first[name]
        assert values[name][1](self.DATA[16 : 16 + 4096]) == first[name]  # the string form agrees

    def test_ten_thousand_regions_keep_at_most_the_bound(self) -> None:
        module = HashModule(self.DATA * 2)
        md5 = module.values()["md5"][0]
        for i in range(10_000):
            md5(i * 16, 16)
        assert len(module.results) <= 256
