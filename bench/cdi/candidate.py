"""F (Candidate Detector Factory): emit a CandidateDetector, or REJECT.

Two lanes (CDI §3F, agreed): RULE PACKS go census → proposal → shadow → gate; MODELS retrain via the
one entry point bench/model/train.py. The factory must be able to reject -- here it refuses any miss
that is not factory-eligible (the two-gate rule), so leakage cannot enter a candidate. Generated code
never loads into production: a rule-pack candidate carries a DECLARATIVE rule, not code.

``file_exfil_candidate`` is the Stage-2 slice-2 candidate: the skills behaviour class (a), a real but
narrow improvement (1/80 wild, 0/3,745 dev-benign FP), whose known limit -- a regex over the curl/scp
shape, evadable by obfuscation -- is recorded so the adversarial gate (acceptance 13) can expose it.
"""

from __future__ import annotations

from typing import Any

from . import schemas

_KINDS = frozenset({"rule", "signal_combination", "feature", "model_update", "ecosystem_logic"})
_LANES = frozenset({"rule_pack", "model"})


class FactoryRejection(Exception):
    """Raised when a candidate cannot be built -- e.g. a source miss is not factory-eligible."""


#: The declarative rule the (a) candidate carries. It names the existing scanner signal rather than
#: shipping code: the agent_intent "file-exfil" intent already produces SUSPECT.AGENT.INTENT.001 at
#: HIGH for third-party skills. The rule pack switches that signal on in the rule_pack lane; no new
#: code loads into the scanner.
FILE_EXFIL_RULE_PACK: dict[str, Any] = {
    "rule_schema_version": "1.0.0",
    "id": "cdi.skill.file_exfil",
    "enforcement": "shadow",  # census → proposal → SHADOW → gate → (team approval) → blocking
    "signal": "agent.intent.file-exfil",
    "emits": {"rule": "SUSPECT.AGENT.INTENT.001", "severity": "HIGH"},
    "scope": {"surface": "skill", "origin": "third_party", "slot": "agent_text"},
}


class CandidateFactory:
    """Build a CandidateDetector, or reject. Stateless; call the static methods."""

    @staticmethod
    def make_candidate(
        *,
        candidate_id: str,
        version: str,
        kind: str,
        lane: str,
        source_misses: list[dict[str, Any]],
        mechanism_addressed: str,
        evidence: str,
        provenance: str,
        expected_gain: str,
        benign_lookalikes: list[str],
        scope: str,
        cost: str,
        train_dataset_digest: str,
        limits: str,
        rollback_conditions: str,
        compatibility: dict[str, Any],
        rule_pack: dict[str, Any] | None = None,
        datasets: list[str] | None = None,
    ) -> dict[str, Any]:
        if kind not in _KINDS:
            raise FactoryRejection(f"kind {kind!r} not in {sorted(_KINDS)}")
        if lane not in _LANES:
            raise FactoryRejection(f"lane {lane!r} not in {sorted(_LANES)}")
        if lane == "rule_pack" and not rule_pack:
            raise FactoryRejection("a rule_pack candidate must carry a declarative rule_pack")
        if not source_misses:
            raise FactoryRejection("a candidate must derive from at least one miss")
        # The two-gate rule: every source miss must be train/dev (split is manifest-owned, passed in
        # on the miss record). A val/held/fresh miss reaching the factory is leakage; refuse it.
        for m in source_misses:
            split = m.get("dataset_membership")
            if split not in schemas.FACTORY_SPLITS:
                raise FactoryRejection(
                    f"miss {m.get('miss_id')!r} split {split!r} is not train/dev; factory refuses it"
                )
        record = {
            "schema_version": schemas.SCHEMA_VERSIONS["CandidateDetector"],
            "candidate_id": candidate_id,
            "version": version,
            "kind": kind,
            "lane": lane,
            "derived_from_miss_ids": [m["miss_id"] for m in source_misses],
            "mechanism_addressed": mechanism_addressed,
            "evidence": evidence,
            "provenance": provenance,
            "expected_gain": expected_gain,
            "benign_lookalikes": list(benign_lookalikes),
            "scope": scope,
            "cost": cost,
            "train_dataset_digest": train_dataset_digest,
            "datasets": list(datasets or []),
            "evaluation_runs": [],
            "limits": limits,
            "rollback_conditions": rollback_conditions,
            "compatibility": compatibility,
            "status": "proposed",
            "rejection_reason": None,
        }
        return schemas.Schemas.validate("CandidateDetector", record)

    @staticmethod
    def file_exfil_candidate(
        source_misses: list[dict[str, Any]], train_dataset_digest: str
    ) -> dict[str, Any]:
        return CandidateFactory.make_candidate(
            candidate_id="cdi.skill.file_exfil",
            version="1.0.0",
            kind="rule",
            lane="rule_pack",
            source_misses=source_misses,
            mechanism_addressed="a local file uploaded to a host off this machine (skills class a)",
            evidence="agent_intent file-exfil intent → SUSPECT.AGENT.INTENT.001 (HIGH, third-party)",
            provenance="skills dev scan, wild family misses (train/dev split)",
            expected_gain="1/80 wild misses recovered at 0/3,745 dev-benign FP (dev measurement)",
            benign_lookalikes=[
                "curl -X POST .../api -d @body.json (JSON body to a documented API)",
                "twine / registry upload of a built artefact",
                "scp to localhost",
            ],
            scope="third-party SKILL.md, agent_text slot",
            cost="a regex over fenced curl/scp directives; negligible runtime",
            train_dataset_digest=train_dataset_digest,
            limits="regex over the curl/scp/requests shape; evadable by obfuscation or a non-curl "
            "uploader -- the adversarial gate (acceptance 13) is expected to expose this",
            rollback_conditions="dev-benign FP > 0.5% on any eval benign set, or a confirmed FP "
            "incident",
            compatibility={"min_scanner_version": "0.7.0", "rule_schema_version": "1.0.0"},
            rule_pack=FILE_EXFIL_RULE_PACK,
        )

    @staticmethod
    def reject(candidate: dict[str, Any], reason: str) -> dict[str, Any]:
        """Record a rejection as a new version of the candidate (append-only), with the reason."""
        rejected = dict(candidate)
        rejected["status"] = "rejected"
        rejected["rejection_reason"] = reason
        return schemas.Schemas.validate("CandidateDetector", rejected)
