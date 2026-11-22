"""SI-I1: a rollback and a false positive each create a record the next loop run reads."""

from __future__ import annotations

from pathlib import Path

import pytest
from bench.cdi.feedback import ACQUIRE, KINDS, Feedback


class TestTheRecords:
    def test_a_rollback_and_an_fp_each_create_a_record_the_next_run_reads(
        self, tmp_path: Path
    ) -> None:
        Feedback.add(tmp_path, "rollback", "cand:7", {"reason": "benign block after release"})
        Feedback.add(tmp_path, "false_positive", "sha:abc", {"rule": "R"})
        records, mark = Feedback.read(tmp_path)
        assert [r["kind"] for r in records] == ["rollback", "false_positive"] and mark == 1

    def test_a_record_is_read_by_exactly_one_run(self, tmp_path: Path) -> None:
        Feedback.add(tmp_path, "miss", "m1")
        _, mark = Feedback.read(tmp_path)
        Feedback.add(tmp_path, "miss", "m2")
        second, mark2 = Feedback.read(tmp_path, mark)
        assert [r["artifact_digest"] for r in second] == ["m2"] and mark2 == 1

    def test_a_run_that_reads_nothing_leaves_the_watermark(self, tmp_path: Path) -> None:
        Feedback.add(tmp_path, "miss", "m1")
        assert Feedback.read(tmp_path, 0) == ([], 0)

    def test_an_empty_log_reads_as_nothing(self, tmp_path: Path) -> None:
        assert Feedback.read(tmp_path) == ([], -1)

    def test_every_kind_is_accepted_and_has_an_ask(self, tmp_path: Path) -> None:
        for kind in KINDS:
            Feedback.add(tmp_path, kind, f"d-{kind}")
        assert set(ACQUIRE) == set(KINDS) and len(Feedback.records(tmp_path)) == 4

    def test_an_unknown_kind_is_refused_and_writes_nothing(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="not in"):
            Feedback.add(tmp_path, "rumour", "x")
        assert Feedback.records(tmp_path) == []

    def test_ids_follow_the_log_and_are_never_reused(self, tmp_path: Path) -> None:
        assert [Feedback.add(tmp_path, "miss", f"d{i}") for i in range(3)] == [0, 1, 2]

    def test_an_existing_record_is_never_changed_by_a_later_add(self, tmp_path: Path) -> None:
        Feedback.add(tmp_path, "miss", "m1")
        first = Feedback.path(tmp_path).read_text(encoding="utf-8").splitlines()[0]
        Feedback.add(tmp_path, "rollback", "c")
        assert Feedback.path(tmp_path).read_text(encoding="utf-8").splitlines()[0] == first

    def test_a_correction_names_the_record_and_one_that_does_not_exist_is_refused(
        self, tmp_path: Path
    ) -> None:
        Feedback.add(tmp_path, "false_positive", "d")
        with pytest.raises(ValueError, match="no record 5"):
            Feedback.add(tmp_path, "false_positive", "d", corrects=5)
        assert Feedback.add(tmp_path, "false_positive", "d2", corrects=0) == 1


class TestWhatTheNextRunAcquires:
    def test_each_kind_gets_its_ask_and_its_artifacts(self, tmp_path: Path) -> None:
        Feedback.add(tmp_path, "rollback", "cand:7")
        Feedback.add(tmp_path, "false_positive", "sha:abc")
        asks = Feedback.acquisition(Feedback.read(tmp_path)[0])
        assert asks["rollback"] == [{"artifact_digest": "cand:7", "ask": ACQUIRE["rollback"]}]
        assert asks["false_positive"][0]["ask"].startswith("acquire legitimate lookalikes")

    def test_a_corrected_record_is_left_out(self, tmp_path: Path) -> None:
        Feedback.add(tmp_path, "false_positive", "wrong")
        Feedback.add(tmp_path, "false_positive", "right", corrects=0)
        asks = Feedback.acquisition(Feedback.records(tmp_path))
        assert [e["artifact_digest"] for e in asks["false_positive"]] == ["right"]

    def test_a_kind_with_no_records_is_not_listed(self, tmp_path: Path) -> None:
        Feedback.add(tmp_path, "miss", "m")
        assert list(Feedback.acquisition(Feedback.records(tmp_path))) == ["miss"]
