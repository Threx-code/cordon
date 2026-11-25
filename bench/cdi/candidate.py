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

from cordon_scanner.analysis.gates.env_gates import EnvGate

from . import schemas
from .manifests import ManifestConflict, Manifests

_KINDS = frozenset({"rule", "signal_combination", "feature", "model_update", "ecosystem_logic"})
_LANES = frozenset({"rule_pack", "model"})
#: What a declarative rule may name: its id and version, where it applies and what it emits. A key outside this list is
#: code (a script, a handler, an expression to run) or something the loader does not read, and a candidate carrying one is
#: refused before it exists.
_DECLARATIVE_KEYS = frozenset(
    {"rule_schema_version", "id", "enforcement", "signal", "emits", "scope"}
)


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


ENV_GATE_RULE_PACK: dict[str, Any] = {
    "rule_schema_version": "1.0.0",
    "id": "cdi.code.env_gate",
    "enforcement": "shadow",
    "signal": "code.env-gate.sensitive",
    "emits": {"rule": "SUSPECT.CODE.ENVGATE.001", "severity": "MEDIUM"},
    "scope": {"surface": "package", "origin": "third_party", "slot": "code"},
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
        manifests: Manifests,
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
        if rule_pack:
            CandidateFactory.require_declarative(rule_pack)
        if not source_misses:
            raise FactoryRejection("a candidate must derive from at least one miss")
        # The two-gate rule: every source miss must be train/dev. The split is read from the dataset manifests by the miss's artifact digest, never from the miss.
        # A val/held/fresh miss reaching the factory is leakage; refuse it. An artifact the manifests do not list, or list in two splits, is refused too.
        for m in source_misses:
            try:
                split = manifests.of_miss(m)
            except ManifestConflict as conflict:
                raise FactoryRejection(f"miss {m.get('miss_id')!r}: {conflict}") from conflict
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
        source_misses: list[dict[str, Any]], train_dataset_digest: str, manifests: Manifests
    ) -> dict[str, Any]:
        return CandidateFactory.make_candidate(
            candidate_id="cdi.skill.file_exfil",
            version="1.0.0",
            kind="rule",
            lane="rule_pack",
            source_misses=source_misses,
            manifests=manifests,
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
    def env_gate_candidate(
        source_misses: list[dict[str, Any]],
        gates: tuple[EnvGate, ...],
        train_dataset_digest: str,
        manifests: Manifests,
    ) -> dict[str, Any]:
        """A shadow rule for the gate shape the misses share; refused when no source carries a gate."""
        if not gates:
            raise FactoryRejection("no environment gate was read from the source misses")
        shapes = sorted({f"{g.variable}->{g.capability}" for g in gates})
        return CandidateFactory.make_candidate(
            candidate_id="cdi.code.env_gate",
            version="1.0.0",
            kind="rule",
            lane="rule_pack",
            source_misses=source_misses,
            manifests=manifests,
            mechanism_addressed="sensitive code reached only where a CI variable is set or unset",
            evidence="gate shapes read from the misses: " + ", ".join(shapes),
            provenance="dev misses, gate read statically (train/dev split)",
            expected_gain="to be measured by the pre-test on cached facts",
            benign_lookalikes=[
                "a build script that installs only on CI",
                "a test helper skipped on CI",
            ],
            scope="package code, install and import paths",
            cost="one parse per source file; the gate is read from the syntax tree",
            train_dataset_digest=train_dataset_digest,
            limits="a gate built from an indirect read of the variable is not seen",
            rollback_conditions="dev-benign FP > 0.5% on any eval benign set, or a confirmed FP incident",
            compatibility={"min_scanner_version": "0.8.0", "rule_schema_version": "1.0.0"},
            rule_pack=ENV_GATE_RULE_PACK,
        )

    @staticmethod
    def reject(candidate: dict[str, Any], reason: str) -> dict[str, Any]:
        """Record a rejection as a new version of the candidate (append-only), with the reason."""
        rejected = dict(candidate)
        rejected["status"] = "rejected"
        rejected["rejection_reason"] = reason
        return schemas.Schemas.validate("CandidateDetector", rejected)

    @staticmethod
    def require_declarative(rule_pack: dict[str, Any]) -> None:
        """A rule pack names what to look for; it carries no code. Refused: a key the loader does not read (which is how
        a script or a handler would ride along), and a value that is not text or a plain mapping of text."""
        outside = sorted(set(rule_pack) - _DECLARATIVE_KEYS)
        if outside:
            raise FactoryRejection(
                f"a candidate is a declarative rule, not code: {', '.join(outside)} is not part of one"
            )
        for key, value in rule_pack.items():
            plain = isinstance(value, str) or (
                isinstance(value, dict)
                and all(isinstance(k, str) and isinstance(v, str) for k, v in value.items())
            )
            if not plain:
                raise FactoryRejection(
                    f"a candidate is a declarative rule, not code: {key} holds more than text"
                )

    @staticmethod
    def judged(candidate: dict[str, Any], decision: dict[str, Any]) -> dict[str, Any]:
        """The candidate after the gate: rejected, with the reasons the gate gave, when the decision rejects it. A decision
        for another candidate is refused, so one candidate's reasons are never written onto another."""
        if decision.get("candidate_id") != candidate["candidate_id"]:
            raise FactoryRejection("that decision is for another candidate")
        if decision.get("outcome") != "reject":
            return candidate
        return CandidateFactory.reject(
            candidate, f"the gate rejected it: {CandidateFactory.why_rejected(decision)}"
        )

    @staticmethod
    def why_rejected(decision: dict[str, Any]) -> str:
        """The gates that did not pass, each with the reason it wrote, and any reason ids the decision lists; or that the
        gate rejected it without saying why."""
        gates = decision.get("gates") if isinstance(decision.get("gates"), dict) else {}
        failed = [
            f"{name} ({gate.get('reason') or 'no reason given'})"
            for name, gate in sorted(gates.items())
            if isinstance(gate, dict) and gate.get("result") not in ("pass", "not_applicable")
        ]
        failed += sorted(str(r) for r in decision.get("reason_ids") or [])
        return "; ".join(failed) or "no reason given"
