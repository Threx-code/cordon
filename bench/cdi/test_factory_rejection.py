"""The factory rejects with a recorded reason, and a candidate that is code is refused by the loader."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path
from typing import Any

import pytest
from bench.cdi.candidate import FILE_EXFIL_RULE_PACK, CandidateFactory, FactoryRejection
from bench.cdi.gate import Gate
from bench.cdi.test_cdi_skeleton import Build
from bench.cdi.test_gate import BEN_CLEAN, GateKit


class Kit:
    @staticmethod
    def candidate() -> dict[str, Any]:
        return CandidateFactory.file_exfil_candidate(
            [Build.miss()], train_dataset_digest="sha256:aa", manifests=Build.manifests("train")
        )

    @staticmethod
    def make(rule_pack: dict[str, Any]) -> dict[str, Any]:
        return CandidateFactory.make_candidate(
            candidate_id="c",
            version="1",
            kind="rule",
            lane="rule_pack",
            source_misses=[Build.miss()],
            manifests=Build.manifests("train"),
            mechanism_addressed="m",
            evidence="e",
            provenance="p",
            expected_gain="g",
            benign_lookalikes=[],
            scope="s",
            cost="c",
            train_dataset_digest="sha256:aa",
            limits="l",
            rollback_conditions="r",
            compatibility={"min_scanner_version": "0.7.0", "rule_schema_version": "1.0.0"},
            rule_pack=rule_pack,
        )


class TestACandidateThatFailsAGateIsRejectedWithItsReason:
    def gate(self, tmp_path: Path, candidate_id: str) -> dict[str, Any]:
        from bench.cdi.test_gate import MAL

        losing = {"m1": (0, [], 1.0), "m2": (1, MAL, 1.0)}
        _, decision = Gate.evaluate(
            {**GateKit.spec(tmp_path, losing, BEN_CLEAN), "candidate_id": candidate_id}
        )
        return decision

    def test_a_losing_candidate_is_recorded_as_rejected_with_the_gates_reasons(
        self, tmp_path: Path
    ) -> None:
        candidate = Kit.candidate()
        decision = self.gate(tmp_path, candidate["candidate_id"])
        assert decision["outcome"] == "reject"
        rejected = CandidateFactory.judged(candidate, decision)
        assert rejected["status"] == "rejected"
        assert rejected["rejection_reason"].startswith("the gate rejected it: ")
        assert "lose_zero" in rejected["rejection_reason"]
        assert candidate["status"] == "proposed" and candidate["rejection_reason"] is None

    def test_a_passing_candidate_is_left_as_it_was(self, tmp_path: Path) -> None:
        from bench.cdi.test_gate import MAL

        candidate = Kit.candidate()
        winning = {"m1": (1, MAL, 1.0), "m2": (1, MAL, 1.0)}
        _, decision = Gate.evaluate(
            {
                **GateKit.spec(tmp_path, winning, BEN_CLEAN),
                "candidate_id": candidate["candidate_id"],
            }
        )
        assert CandidateFactory.judged(candidate, decision) == candidate

    def test_another_candidates_decision_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(FactoryRejection, match="another candidate"):
            CandidateFactory.judged(Kit.candidate(), self.gate(tmp_path, "someone:else"))

    def test_a_decision_with_no_reason_still_records_that_the_gate_rejected_it(self) -> None:
        candidate = Kit.candidate()
        rejected = CandidateFactory.judged(
            candidate,
            {"candidate_id": candidate["candidate_id"], "outcome": "reject", "reason_ids": []},
        )
        assert rejected["rejection_reason"] == "the gate rejected it: no reason given"


class TestCodeIsNotACandidate:
    def test_the_declarative_rule_the_factory_ships_is_accepted(self) -> None:
        assert Kit.make(FILE_EXFIL_RULE_PACK)["lane"] == "rule_pack"

    @pytest.mark.parametrize("key", ["code", "script", "handler", "python", "run", "on_match"])
    def test_a_rule_pack_carrying_a_key_that_is_not_part_of_a_rule_is_refused(
        self, key: str
    ) -> None:
        with pytest.raises(FactoryRejection, match="declarative rule, not code"):
            Kit.make({**FILE_EXFIL_RULE_PACK, key: "import os; os.system('x')"})

    def test_a_value_that_is_more_than_text_is_refused(self) -> None:
        with pytest.raises(FactoryRejection, match="more than text"):
            Kit.make({**FILE_EXFIL_RULE_PACK, "signal": ["a", "b"]})
        with pytest.raises(FactoryRejection, match="more than text"):
            Kit.make({**FILE_EXFIL_RULE_PACK, "emits": {"rule": 7}})


class TestTheScannersLoaderRefusesCode:
    """What reaches a scanner is read by its loader (`FeedRules.install`): only rule packs and their index, nothing else."""

    @staticmethod
    def archive(members: dict[str, bytes]) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
            for name, body in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(body)
                tar.addfile(info, io.BytesIO(body))
        return buffer.getvalue()

    @pytest.mark.parametrize(
        "name",
        ["rulepack-x.py", "rulepack-x.sh", "rulepack-x.yaml.py", "plugin.py", "../rulepack-x.yaml"],
    )
    def test_an_archive_with_a_file_that_is_not_a_rule_pack_is_refused(
        self, name: str, tmp_path: Path, monkeypatch
    ) -> None:
        from cordon_scanner.intel.base import FeedError
        from cordon_scanner.intel.malware.feed_rules import FeedRules

        monkeypatch.setattr(FeedRules, "directory", classmethod(lambda cls: tmp_path / "rules"))
        body = self.archive({"rulepacks.json": b"{}", name: b"print('loaded')"})
        with pytest.raises(FeedError, match="unexpected member"):
            FeedRules.install(body)
        assert not (tmp_path / "rules").exists()

    def test_an_archive_of_only_a_pack_and_its_index_is_installed(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        from cordon_scanner.intel.malware.feed_rules import FeedRules

        monkeypatch.setattr(FeedRules, "directory", classmethod(lambda cls: tmp_path / "rules"))
        FeedRules.install(self.archive({"rulepacks.json": b"{}", "rulepack-x.yaml": b"pack: {}"}))
        assert (tmp_path / "rules" / "rulepack-x.yaml").is_file()
