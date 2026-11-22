"""The CDI B/E/F skeleton on a constructed scan row (the documented shape). Tests the transform and
the safety rules, not malware recall -- recall is the gate's job on real samples."""

from __future__ import annotations

import pytest
from bench.cdi.candidate import CandidateFactory, FactoryRejection
from bench.cdi.featureset import FeatureSetBuilder
from bench.cdi.manifests import ManifestConflict, Manifests
from bench.cdi.miss import Miss
from bench.cdi.schemas import Schemas

# A scan row in the documented shape: findings are 7-tuples, verdict carries package features.
_ROW = {
    "file": "pkg/evil-skill.tgz!SKILL.md",
    "sha256": "abc123",
    "findings": [
        ["SUSPECT.AGENT.INTENT.001", "HIGH", 0.9, "agent", "kit/SKILL.md", 12, "agent_intent"],
        ["MALWARE.PACKAGE.KNOWN.001", "CRITICAL", 1.0, "intel", "", 0, "advisory"],
    ],
    "verdict": {"package": {"skill": 1.0, "n_files": 3.0, "has_readme": 0.0}},
    "exit": 1,
}


class Build:
    """Test fixtures. Stateless; call the static methods."""

    @staticmethod
    def featureset(row=_ROW, versions=None):
        return FeatureSetBuilder.build_featureset(
            row,
            artifact_id="art:evil@1.0",
            ecosystem="skill",
            versions=versions or {"scanner": "afae550"},
        )

    @staticmethod
    def manifests(split="dev"):
        """The one dataset manifest that lists the miss's artifact, in `split`."""
        return Manifests([{"dataset": "d1", "split": split, "artifacts": ["abc123"]}])

    @staticmethod
    def miss(miss_id="miss:1"):
        return Miss.detection_miss(
            miss_id=miss_id,
            artifact_id="art:evil@1.0",
            artifact_digest="abc123",
            label_ref="label:7",
            baseline={"scanner_version": "afae550", "intel_version": "s3", "model_version": None},
            reproduce={
                "command": "cordon scan evil-skill.tgz",
                "scan_output_digest": "sha256:dead",
            },
            detectors_ran=["agent_intent", "capability"],
            absent_or_misweighted=[
                {"what": "file-exfil intent", "why": "upload shape not matched"}
            ],
            failure_mechanism="class a: file read uploaded to an external host, directive in prose",
            needed={"kind": "rule", "note": "agent.intent.file-exfil rule pack"},
        )


class TestFeatureSet:
    def test_content_vs_intel_source(self):
        fs = Build.featureset()
        by_name = {f["name"]: f for f in fs["features"]}
        assert by_name["finding:SUSPECT.AGENT.INTENT.001"]["source"] == "content"
        assert by_name["finding:MALWARE.PACKAGE.KNOWN.001"]["source"] == "intel"
        assert by_name["finding:SUSPECT.AGENT.INTENT.001"]["slot"] == "agent_text"

    def test_digest_is_content_normalised(self):
        # Same content, different intel finding and scanner version -> same featureset_digest.
        row2 = {
            **_ROW,
            "findings": [
                [
                    "SUSPECT.AGENT.INTENT.001",
                    "HIGH",
                    0.9,
                    "agent",
                    "kit/SKILL.md",
                    12,
                    "agent_intent",
                ],
                ["MALWARE.PACKAGE.KNOWN.002", "CRITICAL", 1.0, "intel", "", 0, "advisory"],
            ],
        }
        a = Build.featureset(versions={"scanner": "afae550"})
        b = Build.featureset(row2, versions={"scanner": "ffffffff"})
        assert a["featureset_digest"] == b["featureset_digest"]

    def test_content_change_moves_the_digest(self):
        row2 = {**_ROW, "verdict": {"package": {"skill": 1.0, "n_files": 9.0, "has_readme": 1.0}}}
        assert (
            Build.featureset()["featureset_digest"] != Build.featureset(row2)["featureset_digest"]
        )

    def test_deterministic_and_valid(self):
        assert Build.featureset() == Build.featureset()
        assert Build.featureset()["schema_version"] == "1.0.0"


class TestMiss:
    def test_valid(self):
        assert Build.miss()["schema_version"] == "1.1.0"

    def test_the_miss_carries_no_split(self):
        assert "dataset_membership" not in Build.miss()

    def test_bad_needed_kind_rejected(self):
        with pytest.raises(ValueError):
            Miss.detection_miss(
                miss_id="m",
                artifact_id="a",
                artifact_digest="d",
                label_ref="l",
                baseline={},
                reproduce={},
                detectors_ran=[],
                absent_or_misweighted=[],
                failure_mechanism="x",
                needed={"kind": "wand"},
            )

    def test_eligibility_two_gates(self):
        assert Schemas.eligible_for_factory("confirmed", "train")
        assert Schemas.eligible_for_factory("corroborated", "dev")
        assert not Schemas.eligible_for_factory("silver", "train")
        assert not Schemas.eligible_for_factory("confirmed", "held")


class TestCandidateFactory:
    def test_file_exfil_candidate_from_train_miss(self):
        c = CandidateFactory.file_exfil_candidate(
            [Build.miss()], train_dataset_digest="sha256:aa", manifests=Build.manifests("train")
        )
        assert c["status"] == "proposed"
        assert c["derived_from_miss_ids"] == ["miss:1"]
        assert c["lane"] == "rule_pack"
        assert c["kind"] == "rule"
        assert c["compatibility"]["min_scanner_version"] == "0.7.0"

    def test_factory_refuses_held_miss(self):
        # The leakage guard: a held-split miss must never inform a candidate.
        with pytest.raises(FactoryRejection):
            CandidateFactory.file_exfil_candidate(
                [Build.miss()], train_dataset_digest="sha256:aa", manifests=Build.manifests("held")
            )

    def test_factory_refuses_a_miss_no_manifest_lists(self):
        with pytest.raises(FactoryRejection):
            CandidateFactory.file_exfil_candidate(
                [Build.miss()], train_dataset_digest="sha256:aa", manifests=Manifests([])
            )

    def test_factory_refuses_a_miss_listed_in_two_splits(self):
        both = Manifests(
            [
                {"dataset": "a", "split": "train", "artifacts": ["abc123"]},
                {"dataset": "b", "split": "held", "artifacts": ["abc123"]},
            ]
        )
        with pytest.raises(FactoryRejection, match="more than one split"):
            CandidateFactory.file_exfil_candidate(
                [Build.miss()], train_dataset_digest="sha256:aa", manifests=both
            )

    def test_moving_the_artifact_to_held_in_the_manifest_refuses_the_same_miss(self):
        """The miss is not edited; only the manifest changes, and the factory's answer changes with it."""
        miss = Build.miss()
        before = dict(miss)
        assert CandidateFactory.file_exfil_candidate(
            [miss], train_dataset_digest="sha256:aa", manifests=Build.manifests("dev")
        )
        with pytest.raises(FactoryRejection):
            CandidateFactory.file_exfil_candidate(
                [miss], train_dataset_digest="sha256:aa", manifests=Build.manifests("held")
            )
        assert miss == before

    def test_rule_pack_required(self):
        with pytest.raises(FactoryRejection):
            CandidateFactory.make_candidate(
                candidate_id="c",
                version="1",
                kind="rule",
                lane="rule_pack",
                source_misses=[Build.miss()],
                manifests=Build.manifests(),
                mechanism_addressed="",
                evidence="",
                provenance="",
                expected_gain="",
                benign_lookalikes=[],
                scope="",
                cost="",
                train_dataset_digest="sha256:aa",
                limits="",
                rollback_conditions="",
                compatibility={},
                rule_pack=None,
            )

    def test_reject_is_a_new_version(self):
        c = CandidateFactory.file_exfil_candidate(
            [Build.miss()], train_dataset_digest="sha256:aa", manifests=Build.manifests("train")
        )
        r = CandidateFactory.reject(c, "held-out gain not reproducible")
        assert r["status"] == "rejected"
        assert r["rejection_reason"] == "held-out gain not reproducible"
        assert c["status"] == "proposed"  # original unchanged (append-only)


class TestManifests:
    """Membership is read from the manifests."""

    def test_an_artifact_in_one_manifest_has_that_split(self):
        assert Build.manifests("train").membership("abc123") == "train"

    def test_an_unlisted_artifact_has_none(self):
        assert Build.manifests().membership("nope") is None

    def test_two_manifests_of_the_same_split_agree(self):
        both = Manifests(
            [
                {"dataset": "a", "split": "dev", "artifacts": ["x"]},
                {"dataset": "b", "split": "dev", "artifacts": ["x"]},
            ]
        )
        assert both.membership("x") == "dev"

    def test_two_splits_for_one_artifact_is_a_conflict_naming_both(self):
        both = Manifests(
            [
                {"dataset": "a", "split": "train", "artifacts": ["x"]},
                {"dataset": "b", "split": "held", "artifacts": ["x"]},
            ]
        )
        with pytest.raises(ManifestConflict) as caught:
            both.membership("x")
        assert caught.value.splits == ("held", "train")

    def test_the_split_of_a_miss_follows_its_artifact_digest(self):
        assert Build.manifests("dev").of_miss(Build.miss()) == "dev"
        assert Build.manifests("held").of_miss(Build.miss()) == "held"
