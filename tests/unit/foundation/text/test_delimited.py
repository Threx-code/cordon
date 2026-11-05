"""Delimited.split gives what re.split(r"\\s*,\\s*") gives, in linear time."""

from __future__ import annotations

import random
import re
import time

import pytest

from cordon_scanner.foundation.text.delimited import Delimited


class TestDelimited:
    @pytest.mark.parametrize("separator", [",", ";"])
    def test_same_list_as_the_regex_split(self, separator: str) -> None:
        rng = random.Random(20261030)  # noqa: S311 -- a fixture, not key material
        alphabet = " \t\n" + chr(0xA0) + chr(0x2003) + separator + "1a"  # ASCII and Unicode space
        pattern = re.compile(r"\s*" + re.escape(separator) + r"\s*")
        for _ in range(20_000):
            text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 14)))
            assert Delimited.split(text, separator) == pattern.split(text), repr(text)

    def test_a_long_run_of_space_is_read_once(self) -> None:
        started = time.process_time()
        assert Delimited.split(" " * 2_000_000 + "x", ",") == [" " * 2_000_000 + "x"]
        assert time.process_time() - started < 2
