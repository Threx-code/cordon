"""The policy and the 100 recorded cases the Rego and Cedar exports are proved over (row BP-6-5).

    python tests/kits/export_cases.py write tests/unit/decide/export/golden

writes `cases.json` (each case's inputs and the state `decide()` gave it), `fixture.rego` and `fixture.cedar` (the exports of the
fixture policy). The cases are made by a fixed seed over the inputs the exported semantics read: findings of every category, severity
and confidence, provenance, tags, namespaces, ages, environments, shortfalls of evidence and hard stops. They are synthetic;
nothing in them comes from a corpus.
"""

from __future__ import annotations

import json
import random
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar

from support import ROOT

sys.path.insert(0, str(ROOT / "src"))

CLOCK = datetime(2026, 11, 19, 10, 0, tzinfo=UTC)
CASES = 100
DIGEST = "sha256:" + "ab" * 32


class ExportCases:
    POLICY: ClassVar[dict[str, Any]] = {
        "policy_schema": 2,
        "id": "acme/export-fixture",
        "version": 1,
        "scope": ["acme"],
        "defaults": {
            "default": "review",
            "on_incomplete": {"*": "block", "ci": "warn", "staging": "review"},
            "unresolved": "block",
            "on_gaps": "review",
            "max_intel_age": "1d",
            "bundle_max_age": "7d",
        },
        "expires_at": "2026-12-31T00:00:00Z",
        "rules": [
            {
                "id": "block-malicious",
                "tier": "deny",
                "then": "block",
                "when": {"finding.category": "malicious", "finding.confidence": ">=medium"},
            },
            {
                "id": "review-severe",
                "tier": "deny",
                "then": "review",
                "when": {
                    "finding.severity": ">=high",
                    "finding.confidence": {"in": ["high", "confirmed"]},
                },
            },
            {
                "id": "young-release",
                "tier": "require",
                "then": "review",
                "applies_to": {"subject.kind": "package"},
                "when": {"version.age_days": "<3"},
            },
            {
                "id": "signed-by-us",
                "tier": "require",
                "then": "review",
                "applies_to": {
                    "subject.ecosystem": {"in": ["npm", "pypi"]},
                    "context.environment": "production",
                },
                "require": {
                    "signature.signer": {"glob": "release@acme.*"},
                    "provenance.slsa_level": ">=2",
                },
            },
            {
                "id": "no-scripts-from-strangers",
                "tier": "deny",
                "then": "block",
                "applies_to": {"context.relation": {"in": ["transitive", "bundled"]}},
                "when": {
                    "finding.rule_id": {"glob": "MALWARE.*"},
                    "finding.domain": {"in": ["build", "cicd"]},
                },
            },
            {
                "id": "our-namespace",
                "tier": "allow",
                "then": "allow",
                "when": {"subject.namespace": "@acme"},
            },
            {
                "id": "pinned-with-conditions",
                "tier": "allow",
                "then": "allow_with_conditions",
                "when": {"subject.tags": "pinned"},
            },
        ],
    }

    @classmethod
    def policy(cls):
        from cordon_scanner.decide.decision.compiler import PolicyCompiler
        from cordon_scanner.decide.decision.policy_source import PolicySource

        return PolicyCompiler.compile(PolicySource.from_json(cls.POLICY))

    @classmethod
    def inputs(cls) -> list[dict[str, Any]]:
        from cordon_scanner.decide.decision.evidence import FindingFact

        rng = random.Random(20261119)  # noqa: S311 -- a fixed seed for synthetic cases, not a secret
        cases = []
        for number in range(CASES):
            findings = [
                {
                    "rule_id": rng.choice(
                        [
                            "MALWARE.EXFIL.001",
                            "MALWARE.DROPPER.002",
                            "SUSPECT.SCRIPT.001",
                            "POLICY.PACKAGE.001",
                        ]
                    ),
                    "severity": rng.choice(FindingFact.SEVERITIES),
                    "confidence": rng.choice(FindingFact.CONFIDENCES),
                    "category": rng.choices(
                        ["malicious", "suspicious", "vulnerable", "policy"], weights=[1, 4, 3, 4]
                    )[0],
                    "domain": rng.choice(["build", "cicd", "source", "dependency", "malware"]),
                    "path": f"src/f{rng.randrange(9)}.js",
                }
                for _ in range(rng.choice([0, 0, 0, 0, 1, 1, 2, 3]))
            ]
            released = rng.choice(
                ["2026-11-18T00:00:00Z", "2026-11-16T00:00:00Z", "2026-06-01T00:00:00Z", None]
            )
            artifact = {
                "kind": rng.choice(
                    ["package", "package", "package", "package", "mcp_server", "agent_skill"]
                ),
                "subject_id": f"pkg:npm/case-{number}",
                "digest": DIGEST,
                "ecosystem": rng.choice(["npm", "pypi", "cargo", None]),
                "namespace": rng.choice(["@acme", "@acme", "@acme", "@other", None]),
                "tags": rng.choice([[], ["pinned"], ["critical"], ["pinned", "critical"]]),
            }
            if released:
                artifact["released_at"] = released
            evidence: dict[str, Any] = {"findings": findings}
            if rng.random() < 0.45:
                evidence["provenance"] = {
                    "slsa_level": rng.choice([1, 2, 2, 3, 3]),
                    "signer": rng.choice(
                        ["release@acme.example", "release@acme.example", "someone@else.example"]
                    ),
                    "verified": rng.random() < 0.85,
                }
            for name, chance in (
                ("revoked", 0.02),
                ("kill_listed", 0.02),
                ("unresolved", 0.04),
            ):
                if rng.random() < chance:
                    evidence[name] = True
            if rng.random() < 0.02:
                evidence["integrity_ok"] = False
            if rng.random() < 0.02:
                evidence["intel"] = [
                    {
                        "kind": "known_malware",
                        "id": "MAL-1",
                        "source": "osv",
                        "first_seen": "2026-11-01T00:00:00Z",
                    }
                ]
            if rng.random() < 0.05:
                evidence["required_missing"] = ["sbom"]
            if rng.random() < 0.05:
                evidence["complete"] = False
            if rng.random() < 0.05:
                evidence["gaps"] = [
                    {"rule_id": "SUSPECT.PACKAGE.UNPARSEABLE.001", "path": "lib/a.js"}
                ]
            context: dict[str, Any] = {
                "point": rng.choice(["cli", "firewall", "ci_gate", "agent_hook"]),
                "environment": rng.choice(["production", "ci", "ci", "staging", "dev"]),
                "relation": rng.choice(["direct", "transitive", "bundled"]),
                "scope_path": ["acme"],
            }
            if rng.random() < 0.1:
                context["bundle_age_s"] = rng.choice([3600, 9 * 86400])
            if rng.random() < 0.1:
                context["intel_age_s"] = rng.choice([3600, 3 * 86400])
            cases.append({"artifact": artifact, "context": context, "evidence": evidence})
        return cases

    @classmethod
    def recorded(cls) -> list[dict[str, Any]]:
        """The inputs with the state `decide()` gave each."""
        from cordon_scanner.decide.decision.decider import Decider
        from cordon_scanner.decide.decision.evidence import ArtifactRef, Context, EvidenceSet

        policy = cls.policy()
        out = []
        for case in cls.inputs():
            decision = Decider.decide(
                ArtifactRef.from_json(case["artifact"]),
                Context.from_json(case["context"]),
                policy,
                EvidenceSet.from_json(case["evidence"]),
                CLOCK,
            )
            out.append({**case, "state": decision.state})
        return out

    @classmethod
    def write(cls, directory: Path) -> None:
        from cordon_scanner.decide.export.cedar import CedarExporter
        from cordon_scanner.decide.export.rego import RegoExporter
        from cordon_scanner.decide.export.table import ExportTable

        directory.mkdir(parents=True, exist_ok=True)
        table = ExportTable.of(cls.policy())
        (directory / "cases.json").write_text(
            json.dumps(
                {"clock": "2026-11-19T10:00:00Z", "cases": cls.recorded()}, indent=1, sort_keys=True
            )
            + "\n",
            encoding="utf-8",
        )
        (directory / "fixture.rego").write_text(RegoExporter.render(table), encoding="utf-8")
        (directory / "fixture.cedar").write_text(CedarExporter.render(table), encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "write":
        ExportCases.write(Path(sys.argv[2]))
