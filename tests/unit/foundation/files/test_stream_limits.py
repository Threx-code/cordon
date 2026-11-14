"""What a scan reads of an oversized file in windows: per member and per scan (the owner's rule: never read
only part of a file), each a Limits field with a hard maximum in code that configuration cannot pass."""

from __future__ import annotations

import multiprocessing
from pathlib import Path

import pytest

from cordon_scanner.foundation.errors import LimitError
from cordon_scanner.foundation.files.stream_budget import StreamBudget
from cordon_scanner.foundation.limits import (
    DEFAULT_LIMITS,
    HARD_MAX_STREAM_BYTES,
    HARD_MAX_STREAM_TOTAL_BYTES,
    HOOK_LIMITS,
    Limits,
)

GIB = 1024**3


class TestTheLimits:
    def test_a_member_is_read_to_four_gib_and_a_scan_to_sixteen(self) -> None:
        assert DEFAULT_LIMITS.max_stream_bytes == 4 * GIB
        assert DEFAULT_LIMITS.max_stream_total_bytes == 16 * GIB

    def test_the_hard_maxima_are_in_code(self) -> None:
        assert HARD_MAX_STREAM_BYTES == 16 * GIB
        assert HARD_MAX_STREAM_TOTAL_BYTES == 64 * GIB
        assert Limits().merged(max_stream_bytes=16 * GIB).max_stream_bytes == 16 * GIB
        assert Limits().merged(max_stream_total_bytes=64 * GIB).max_stream_total_bytes == 64 * GIB

    @pytest.mark.parametrize(
        ("name", "value"),
        [("max_stream_bytes", 16 * GIB + 1), ("max_stream_total_bytes", 64 * GIB + 1)],
    )
    def test_configuration_cannot_pass_them(self, name: str, value: int) -> None:
        with pytest.raises(LimitError, match=name):
            Limits().merged(**{name: value})
        with pytest.raises(LimitError, match=name):
            Limits.from_dict({name: value})

    def test_a_scan_total_of_zero_is_refused_as_every_other_budget_is(self) -> None:
        with pytest.raises(LimitError, match="max_stream_total_bytes"):
            Limits().merged(max_stream_total_bytes=0)

    def test_policy_takes_the_stricter_of_each(self) -> None:
        strict = Limits(max_stream_bytes=GIB, max_stream_total_bytes=2 * GIB)
        merged = DEFAULT_LIMITS.stricter_of(strict)
        assert (merged.max_stream_bytes, merged.max_stream_total_bytes) == (GIB, 2 * GIB)

    def test_the_hook_profile_still_turns_the_windows_off(self) -> None:
        assert HOOK_LIMITS.max_stream_bytes == 0


class TestTheLedger:
    """`StreamBudget.charge`: a scan's total, kept in a file of the scan's budget directory so every worker
    of the scan charges one count."""

    def test_a_charge_within_the_ceiling_is_taken_and_one_past_it_is_refused(
        self, tmp_path: Path
    ) -> None:
        directory = str(tmp_path)
        assert StreamBudget.charge(directory, 600, 1000)
        assert not StreamBudget.charge(directory, 600, 1000)
        assert StreamBudget.spent(directory) == 600

    def test_a_refusal_takes_nothing_so_a_smaller_one_after_it_still_fits(
        self, tmp_path: Path
    ) -> None:
        directory = str(tmp_path)
        assert StreamBudget.charge(directory, 900, 1000)
        assert not StreamBudget.charge(directory, 200, 1000)
        assert StreamBudget.charge(directory, 100, 1000)
        assert StreamBudget.spent(directory) == 1000

    def test_nothing_to_charge_is_always_allowed(self, tmp_path: Path) -> None:
        assert StreamBudget.charge(str(tmp_path), 0, 1)
        assert StreamBudget.spent(str(tmp_path)) == 0

    def test_a_scan_with_no_directory_has_no_total(self) -> None:
        assert StreamBudget.charge(None, 1 << 60, 1)

    def test_workers_of_one_scan_charge_one_count(self, tmp_path: Path) -> None:
        directory = str(tmp_path)
        context = multiprocessing.get_context("spawn")
        with context.Pool(4) as pool:
            taken = pool.starmap(StreamBudget.charge, [(directory, 100, 1000)] * 24)
        assert sum(taken) == 10
        assert StreamBudget.spent(directory) == 1000

    def test_a_ledger_nobody_can_parse_refuses_rather_than_passes(self, tmp_path: Path) -> None:
        (tmp_path / StreamBudget.LEDGER).write_bytes(b"not eight bytes")
        assert not StreamBudget.charge(str(tmp_path), 1, 1 << 40)
