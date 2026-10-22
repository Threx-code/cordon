"""The CDI B/E/F skeleton on a constructed scan row (the documented shape). Tests the transform and
the safety rules, not malware recall -- recall is the gate's job on real samples."""

from __future__ import annotations

import pytest
from bench.cdi import candidate, featureset, miss, schemas

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


def _featureset(row=_ROW, versions=None):
    return featureset.build_featureset(
        row, artifact_id="art:evil@1.0", ecosystem="skill", versions=versions or {"scanner": "afae550"}
    )


class TestFeatureSet:
    def test_content_vs_intel_source(self):
        fs = _featureset()
        by_name = {f["name"]: f for f in fs["features"]}
        assert by_name["finding:SUSPECT.AGENT.INTENT.001"]["source"] == "content"
        assert by_name["finding:MALWARE.PACKAGE.KNOWN.001"]["source"] == "intel"
        assert by_name["finding:SUSPECT.AGENT.INTENT.001"]["slot"] == "agent_text"

    def test_digest_is_content_normalised(self):
        # Same content, different intel finding and scanner version -> same featureset_digest.
        row2 = dict(_ROW)
        row2 = {
            **_ROW,
            "findings": [
                ["SUSPECT.AGENT.INTENT.001", "HIGH", 0.9, "agent", "kit/SKILL.md", 12, "agent_intent"],
                ["MALWARE.PACKAGE.KNOWN.002", "CRITICAL", 1.0, "intel", "", 0, "advisory"],
            ],
        }
        a = _featureset(versions={"scanner": "afae550"})
        b = _featureset(row2, versions={"scanner": "ffffffff"})
        assert a["featureset_digest"] == b["featureset_digest"]

    def test_content_change_moves_the_digest(self):
        row2 = {**_ROW, "verdict": {"package": {"skill": 1.0, "n_files": 9.0, "has_readme": 1.0}}}
        assert _featureset()["featureset_digest"] != _featureset(row2)["featureset_digest"]

    def test_deterministic_and_valid(self):
        assert _featureset() == _featureset()
        assert _featureset()["schema_version"] == "1.0.0"


def _miss(split="dev", miss_id="miss:1"):
    return miss.detection_miss(
        miss_id=miss_id,
        artifact_id="art:evil@1.0",
        artifact_digest="abc123",
        label_ref="label:7",
        dataset_membership=split,
        baseline={"scanner_version": "afae550", "intel_version": "s3", "model_version": None},
        reproduce={"command": "cordon scan evil-skill.tgz", "scan_output_digest": "sha256:deadbeef"},
        detectors_ran=["agent_intent", "capability"],
        absent_or_misweighted=[{"what": "file-exfil intent", "why": "upload shape not matched"}],
        failure_mechanism="class a: file read uploaded to an external host, directive in prose",
        needed={"kind": "rule", "note": "agent.intent.file-exfil rule pack"},
    )


class TestMiss:
    def test_valid(self):
        assert _miss()["schema_version"] == "1.0.0"

    def test_bad_needed_kind_rejected(self):
        with pytest.raises(ValueError):
            miss.detection_miss(
                miss_id="m", artifact_id="a", artifact_digest="d", label_ref="l",
                dataset_membership="dev", baseline={}, reproduce={}, detectors_ran=[],
                absent_or_misweighted=[], failure_mechanism="x", needed={"kind": "wand"},
            )

    def test_eligibility_two_gates(self):
        assert schemas.eligible_for_factory("confirmed", "train")
        assert schemas.eligible_for_factory("corroborated", "dev")
        assert not schemas.eligible_for_factory("silver", "train")
        assert not schemas.eligible_for_factory("confirmed", "held")


class TestCandidateFactory:
    def test_file_exfil_candidate_from_train_miss(self):
        c = candidate.file_exfil_candidate([_miss(split="train")], train_dataset_digest="sha256:aa")
        assert c["status"] == "proposed"
        assert c["derived_from_miss_ids"] == ["miss:1"]
        assert c["lane"] == "rule_pack"
        assert c["kind"] == "rule"
        assert c["compatibility"]["min_scanner_version"] == "0.7.0"

    def test_factory_refuses_held_miss(self):
        # The leakage guard: a held-split miss must never inform a candidate.
        with pytest.raises(candidate.FactoryRejection):
            candidate.file_exfil_candidate([_miss(split="held")], train_dataset_digest="sha256:aa")

    def test_rule_pack_required(self):
        with pytest.raises(candidate.FactoryRejection):
            candidate.make_candidate(
                candidate_id="c", version="1", kind="rule", lane="rule_pack",
                source_misses=[_miss()], mechanism_addressed="", evidence="", provenance="",
                expected_gain="", benign_lookalikes=[], scope="", cost="",
                train_dataset_digest="sha256:aa", limits="", rollback_conditions="",
                compatibility={}, rule_pack=None,
            )

    def test_reject_is_a_new_version(self):
        c = candidate.file_exfil_candidate([_miss(split="train")], train_dataset_digest="sha256:aa")
        r = candidate.reject(c, "held-out gain not reproducible")
        assert r["status"] == "rejected"
        assert r["rejection_reason"] == "held-out gain not reproducible"
        assert c["status"] == "proposed"  # original unchanged (append-only)
