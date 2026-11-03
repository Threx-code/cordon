"""The scan's copy budget (notes/74 addendum): the binary readers' owned whole copies, across every worker of a
scan, at most `CopyBudget.BYTES` at once. Slots are flock'd files in the scan's own directory, so a killed
holder frees its share at once, and a wait past the deadline is a gap, never a hang. No wall-time asserts:
every wait here is bounded by a deadline already past, or by a holder that has gone."""

from __future__ import annotations

import multiprocessing
import time

import pytest

from cordon_scanner.detect.binary.copy_budget import CopyBudget

MIB = 1 << 20


class BudgetKit:
    @staticmethod
    def hold_forever(
        directory: str, nbytes: int, ready
    ) -> None:  # pragma: no cover - runs in a child
        budget = CopyBudget(directory)
        with budget.hold(nbytes, deadline=None) as held:
            assert held
            ready.set()
            time.sleep(3600)


class TestTheBudget:
    def test_a_copy_within_the_budget_is_held_and_released(self, tmp_path) -> None:
        budget = CopyBudget(str(tmp_path))
        with budget.hold(10 * MIB, deadline=None) as held:
            assert held
        with budget.hold(CopyBudget.BYTES, deadline=time.monotonic() - 1) as again:
            assert again, "the slots came back when the first copy was released"

    def test_two_copies_past_the_budget_do_not_both_hold(self, tmp_path) -> None:
        budget = CopyBudget(str(tmp_path))
        with (
            budget.hold(200 * MIB, deadline=None) as first,
            CopyBudget(str(tmp_path)).hold(100 * MIB, deadline=time.monotonic() - 1) as second,
        ):
            assert first
            assert not second, "only 56 MiB were free"

    def test_copies_that_fit_together_both_hold(self, tmp_path) -> None:
        with (
            CopyBudget(str(tmp_path)).hold(100 * MIB, deadline=None) as first,
            CopyBudget(str(tmp_path)).hold(100 * MIB, deadline=time.monotonic() - 1) as second,
        ):
            assert first and second

    def test_a_member_larger_than_the_budget_reads_alone(self, tmp_path) -> None:
        budget = CopyBudget(str(tmp_path))
        with (
            budget.hold(CopyBudget.BYTES * 2, deadline=None) as held,
            CopyBudget(str(tmp_path)).hold(1, deadline=time.monotonic() - 1) as other,
        ):
            assert held and held.alone
            assert not other, "nothing else holds a slot while it reads"

    def test_a_wait_past_the_deadline_is_refused_not_a_hang(self, tmp_path) -> None:
        with (
            CopyBudget(str(tmp_path)).hold(CopyBudget.BYTES, deadline=None),
            CopyBudget(str(tmp_path)).hold(MIB, deadline=time.monotonic() - 1) as late,
        ):
            assert not late
            assert "deadline" in late.reason

    def test_a_killed_holder_frees_its_slots(self, tmp_path) -> None:
        context = multiprocessing.get_context("spawn")
        ready = context.Event()
        child = context.Process(
            target=BudgetKit.hold_forever, args=(str(tmp_path), CopyBudget.BYTES, ready)
        )
        child.start()
        try:
            assert ready.wait(60), "the holder never took its slots"
            with CopyBudget(str(tmp_path)).hold(MIB, deadline=time.monotonic() - 1) as blocked:
                assert not blocked
            child.kill()
            child.join(60)
            with CopyBudget(str(tmp_path)).hold(
                CopyBudget.BYTES, deadline=time.monotonic() + 30
            ) as freed:
                assert freed, "the kernel released the dead holder's locks"
        finally:
            if child.is_alive():
                child.kill()
                child.join(60)

    def test_with_no_directory_there_is_no_budget(self) -> None:
        with CopyBudget(None).hold(CopyBudget.BYTES * 4, deadline=time.monotonic() - 1) as held:
            assert held, "a scan without a budget directory reads as before"


class TestInTheReaders:
    @pytest.mark.parametrize("held_by_other", [True, False])
    def test_the_whole_copy_waits_for_the_budget(self, tmp_path, held_by_other) -> None:
        from cordon_scanner.detect.base import FileUnit
        from cordon_scanner.detect.binary.whole_bytes import WholeBytes
        from cordon_scanner.foundation.content import FileContent
        from cordon_scanner.foundation.limits import Limits
        from kits.paddedkit import PaddedKit

        path = tmp_path / "padded.exe"
        path.write_bytes(PaddedKit.pe())
        content = FileContent.load(path, path.name, Limits())
        assert isinstance(content, FileContent)
        unit = FileUnit(content=content, language=None, opens=str(path))
        budget_dir = tmp_path / "budget"
        budget_dir.mkdir()
        other = CopyBudget(str(budget_dir)).hold(CopyBudget.BYTES, deadline=None)
        held = other.__enter__() if held_by_other else None
        try:
            with WholeBytes.held(unit, str(budget_dir), time.monotonic() - 1) as whole:
                pass
        finally:
            if held is not None:
                other.__exit__(None, None, None)
        if held_by_other:
            assert whole.data is unit.content.raw and "copy budget" in whole.gap
        else:
            assert whole.gap == "" and len(whole.data) == unit.content.size
