"""The determinism goldens for `decide()` (design spec 21.2, M1 acceptance (a)): 2,000 fixed cases and the sha256 of each decision.

A case is (a policy, an artifact, a context, the evidence, a clock) drawn from small pools by a fixed rule: 40 policies x 50
evidence sets, each with the artifact, context and clock the case's position picks. The pools are built here from repository
fixtures only and written to `tests/unit/decide/decision/golden/cases.json`: the subjects are the ids of
`tests/unit/contracts/golden_ids.json`, the rule ids are the scanner's own, the findings and policies are synthetic. Nothing is
drawn from a corpus. The decision of each case (the `decision/v1` predicate, as canonical JSON) is hashed and written to
`golden/envelopes.json` with one digest over them all and the digest of `cases.json` itself, so an input cannot change unseen.

The test (`test_golden_decisions.py`) compiles every policy, decides every case and compares; PR CI runs it on three
operating systems and five Pythons. After an intended change to a decision, regenerate and review the diff:

    python tests/kits/decision_goldens.py write tests/unit/decide/decision/golden tests/unit/contracts/golden_ids.json

and recompute without writing (what a hash seed or a locale must not change; exit 1 on a difference):

    python tests/kits/decision_goldens.py check tests/unit/decide/decision/golden
"""

from __future__ import annotations

import hashlib
import itertools
import json
import sys
from pathlib import Path
from typing import Any, ClassVar

from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.decide.decision.compiler import PolicyCompiler
from cordon_scanner.decide.decision.decider import Decider
from cordon_scanner.decide.decision.evidence import ArtifactRef, Context, EvidenceSet
from cordon_scanner.decide.decision.legacy import LegacyBridge
from cordon_scanner.decide.decision.policy_source import PolicySource
from cordon_scanner.decide.decision.records import Instants
from cordon_scanner.decide.decision.table import CompiledPolicy
from cordon_scanner.foundation.taxonomy import ThreatDomain

CASES_FILE = "cases.json"
ENVELOPES_FILE = "envelopes.json"
POLICIES = 40
EVIDENCE = 50


class Pools:
    """The input pools, as JSON."""

    RULES: ClassVar[list[dict[str, Any]]] = [
        {
            "id": "deny-malicious",
            "tier": "deny",
            "then": "block",
            "when": {"finding.category": "malicious", "finding.confidence": ">=medium"},
        },
        {
            "id": "deny-high",
            "tier": "deny",
            "then": "review",
            "when": {"finding.severity": ">=high", "finding.confidence": ">=medium"},
        },
        {
            "id": "young-release",
            "tier": "require",
            "then": "review",
            "when": {"version.age_days": "<3d"},
        },
        {
            "id": "provenance-critical",
            "tier": "require",
            "then": "block",
            "applies_to": {"subject.tags": "critical"},
            "require": {"provenance.slsa_level": ">=2"},
        },
        {
            "id": "allow-internal",
            "tier": "allow",
            "then": "allow",
            "when": {"subject.namespace": "@acme"},
            "obligations": ["O002"],
        },
    ]

    #: Defaults of the twelve plain v2 policies: (on_incomplete, exceptions, default, the rest).
    DEFAULTS: ClassVar[list[dict[str, Any]]] = [
        {"on_incomplete": "block", "exceptions": "allow"},
        {"on_incomplete": {"*": "review", "production": "block"}, "exceptions": "review"},
        {"on_incomplete": "warn", "exceptions": "none"},
        {"on_incomplete": "block", "exceptions": "allow", "default": "review"},
        {"on_incomplete": "review", "unresolved": "review", "on_gaps": "review"},
        {"on_incomplete": "block", "default": "allow_with_conditions"},
        {"on_incomplete": "block", "max_intel_age": "1d", "bundle_max_age": "30d"},
        {"on_incomplete": "warn", "max_intel_age": "7d", "warn_until_measured": ["npm", "pypi"]},
        {"on_incomplete": "block", "warn_until_measured": ["pypi"], "clock_bucket_s": 300},
        {"on_incomplete": "block", "exceptions": "review", "default": "block"},
        {"on_incomplete": {"*": "warn", "dev": "block"}, "unresolved": "warn"},
        {"on_incomplete": "block", "clock_bucket_s": 1},
    ]

    @staticmethod
    def digest(index: int) -> str:
        return ArtifactDigests.of_bytes(f"golden artifact {index}".encode())

    @classmethod
    def source(cls, **parts: Any) -> dict[str, Any]:
        return {
            "policy_schema": 2,
            "id": "acme/production",
            "version": 14,
            "scope": ["acme"],
            **parts,
        }

    @classmethod
    def policies(cls) -> list[dict[str, Any]]:
        """40 policy chains (root first): the legacy grid sampled, plain v2 variants, mandatory parents with children,
        and policies built around approvals and allow rules."""
        found: list[dict[str, Any]] = []
        grid = LegacyBridge.policy_grid()
        for index in range(0, len(grid), 97):
            found.append(
                {
                    "name": f"legacy-{index}",
                    "chain": [{**LegacyBridge.source(grid[index]).to_json(), "version": 1 + index}],
                }
            )
        for index, defaults in enumerate(cls.DEFAULTS):
            extra = {"expires_at": "2026-11-17T08:01:30Z"} if index == 11 else {}
            found.append(
                {
                    "name": f"v2-{index}",
                    "chain": [cls.source(rules=cls.RULES, defaults=defaults, **extra)],
                }
            )
        parent = cls.source(
            id="acme",
            version=3,
            scope=["acme"],
            mandatory=True,
            rules=cls.RULES[:2],
            defaults={"on_incomplete": "block", "exceptions": "review", "max_intel_age": "7d"},
        )
        for index, rules in enumerate(
            (
                [],
                [cls.RULES[2]],
                [cls.RULES[3]],
                [cls.RULES[4]],
                [cls.RULES[2], cls.RULES[3], cls.RULES[4]],
            )
        ):
            child = cls.source(
                id="acme/payments",
                version=2 + index,
                scope=["acme", "payments"],
                extends=["acme"],
                rules=rules,
                defaults={"max_intel_age": "1d"} if index % 2 else {"exceptions": "none"},
            )
            found.append({"name": f"chain-{index}", "chain": [parent, child]})
        grandchild = cls.source(
            id="acme/payments/eu",
            version=1,
            scope=["acme", "payments", "eu"],
            extends=["acme/payments"],
            rules=[
                {
                    "id": "eu-review",
                    "tier": "deny",
                    "then": "review",
                    "when": {"finding.category": "policy"},
                }
            ],
        )
        middle = cls.source(
            id="acme/payments",
            version=2,
            scope=["acme", "payments"],
            extends=["acme"],
            rules=[cls.RULES[2]],
        )
        found.append({"name": "chain-3-deep", "chain": [parent, middle, grandchild]})
        for index in range(len(found), POLICIES):
            found.append(
                {
                    "name": f"allow-{index}",
                    "chain": [
                        cls.source(
                            version=index,
                            rules=[cls.RULES[4], cls.RULES[3], cls.RULES[0]][: 1 + index % 3],
                            defaults={
                                "default": ("review", "allow", "allow_with_conditions")[index % 3],
                                "on_incomplete": ("block", "review")[index % 2],
                                "exceptions": ("allow", "review", "none")[index % 3],
                            },
                        )
                    ],
                }
            )
        return found[:POLICIES]

    @classmethod
    def artifacts(cls, golden_ids: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """12 subjects from the golden ids fixture: the first of each of the ten kinds the goldens were recorded with, then two
        more packages. The eleventh kind (`third_party_integration`) is left out of the pool so the recorded decisions stay what they were."""
        picked: list[dict[str, Any]] = []
        seen: set[str] = {"third_party_integration"}
        for entry in golden_ids:
            if entry["kind"] not in seen:
                seen.add(entry["kind"])
                picked.append(entry)
        picked += [entry for entry in golden_ids if entry["id"].startswith("pkg:npm/")][5:6]
        picked += [entry for entry in golden_ids if entry["id"].startswith("pkg:pypi/")][5:6]
        found = []
        for index, entry in enumerate(picked[:12]):
            ecosystem = (
                entry["id"].split("/", 1)[0].removeprefix("pkg:")
                if entry["id"].startswith("pkg:")
                else None
            )
            found.append(
                {
                    "kind": entry["kind"],
                    "subject_id": entry["id"],
                    "digest": None if index % 5 == 4 else cls.digest(index),
                    "version": f"1.{index}.0",
                    "ecosystem": ecosystem if ecosystem in {"npm", "pypi"} else None,
                    "namespace": "@acme" if index % 4 == 0 else None,
                    "tags": ["critical"] if index % 3 == 0 else [],
                    "released_at": ("2026-06-01T00:00:00Z", "2026-11-16T12:00:00Z", None)[
                        index % 3
                    ],
                }
            )
        return found

    @staticmethod
    def contexts() -> list[dict[str, Any]]:
        shapes = [
            ("ci_gate", "production", ["acme", "payments"], "human", "direct", True, None, None),
            ("cli", "dev", [], "human", "direct", True, 3600, 3600),
            ("firewall", "production", ["acme"], "workload", "transitive", True, None, 864000),
            ("agent_hook", "dev", ["acme", "ai"], "agent:claude-code", "tool", True, 3600, None),
            (
                "deploy_admission",
                "staging",
                ["acme", "payments", "eu"],
                "workload",
                "runtime",
                False,
                90000,
                90000,
            ),
            ("ide", "dev", ["other"], "human", "direct", True, None, None),
            (
                "inventory_sweep",
                "production",
                ["acme", "payments"],
                "workload",
                "bundled",
                True,
                3000000,
                3000000,
            ),
            ("ci_gate", "ci", ["acme"], "workload", "transitive", True, 60, 60),
            ("cli", "production", ["acme", "payments"], "human", "direct", False, None, None),
            ("firewall", "dev", [], "workload", "runtime", True, 600, 700000),
        ]
        keys = (
            "point",
            "environment",
            "scope_path",
            "actor",
            "relation",
            "online",
            "bundle_age_s",
            "intel_age_s",
        )
        return [dict(zip(keys, shape, strict=True)) for shape in shapes]

    @staticmethod
    def clocks() -> list[str]:
        return [
            "2026-11-17T08:00:00Z",
            "2026-11-17T08:00:59Z",
            "2026-11-17T08:01:00Z",
            "2026-11-17T08:00:00.500000Z",
            "2026-11-18T08:00:00+00:00",
            "2026-12-31T23:59:59Z",
        ]

    @classmethod
    def finding(
        cls, index: int, category: str, severity: str, confidence: str, **extra: Any
    ) -> dict[str, Any]:
        domains = sorted(domain.value for domain in ThreatDomain)
        return {
            "rule_id": f"GOLDEN.{category.upper()}.{index:03d}",
            "severity": severity,
            "confidence": confidence,
            "category": category,
            "domain": domains[index % len(domains)],
            "path": f"src/f{index % 7}.py",
            "line": 1 + index % 40,
            **extra,
        }

    @classmethod
    def evidence(cls) -> list[dict[str, Any]]:
        """50 evidence sets: nothing, single findings, several, gaps, incomplete, intel, hard stops, missing facts,
        provenance, and approvals and exceptions (bound to the digest of artifact `n % 12`)."""
        found: list[dict[str, Any]] = [{}]
        categories = ("malicious", "suspicious", "vulnerable", "policy", "operational")
        for index, (category, (severity, confidence)) in enumerate(
            itertools.product(categories, (("medium", "medium"), ("high", "confirmed")))
        ):
            found.append({"findings": [cls.finding(index, category, severity, confidence)]})
        found.append(
            {
                "findings": [
                    cls.finding(i, "suspicious", ("low", "medium", "high")[i % 3], "medium")
                    for i in range(3)
                ]
            }
        )
        found.append(
            {
                "findings": [
                    cls.finding(
                        i,
                        ("malicious", "policy", "vulnerable")[i % 3],
                        ("critical", "info")[i % 2],
                        ("high", "low")[i % 2],
                    )
                    for i in reversed(range(12))
                ]
            }
        )
        found.append(
            {
                "findings": [
                    cls.finding(5, "suspicious", "high", "high", line=line) for line in (9, 3, 30)
                ]
            }
        )
        found.append(
            {
                "findings": [
                    cls.finding(
                        1, "malicious", "critical", "confirmed", evidence_hash="sha256:" + "a" * 64
                    )
                ]
            }
        )
        found.append(
            {
                "findings": [cls.finding(2, "vulnerable", "high", "high")],
                "gaps": [{"rule_id": "OPERATIONAL.SOURCE.UNPARSED", "path": "a.py"}],
            }
        )
        found.append(
            {
                "findings": [cls.finding(4, "policy", "medium", "high")],
                "provenance": {"slsa_level": 1, "verified": True},
            }
        )
        found.append({"gaps": [{"rule_id": "OPERATIONAL.SOURCE.UNPARSED", "path": "a.py"}]})
        found.append(
            {
                "gaps": [
                    {"rule_id": "OPERATIONAL.ARCHIVE.REFUSED", "path": "b.tar"},
                    {"rule_id": "OPERATIONAL.SOURCE.UNPARSED"},
                ]
            }
        )
        found.append(
            {
                "gaps": [{"rule_id": "OPERATIONAL.SOURCE.UNPARSED", "path": "a.py"}],
                "findings": [cls.finding(3, "suspicious", "medium", "medium")],
            }
        )
        found.append({"complete": False})
        found.append({"complete": False, "findings": [cls.finding(6, "malicious", "high", "high")]})
        known = {
            "kind": "known_malware",
            "id": "MAL-2026-0001",
            "source": "golden",
            "first_seen": "2026-10-01T00:00:00Z",
        }
        found.append({"intel": [known]})
        found.append({"intel": [{**known, "withdrawn": True}]})
        found.append(
            {
                "intel": [
                    {
                        "kind": "advisory",
                        "id": "GHSA-golden-0001",
                        "source": "golden",
                        "first_seen": "2026-09-01T00:00:00Z",
                    }
                ]
            }
        )
        found.append(
            {
                "intel": [
                    known,
                    {
                        "kind": "advisory",
                        "id": "GHSA-golden-0002",
                        "source": "golden",
                        "first_seen": "2026-09-02T00:00:00Z",
                    },
                ],
                "findings": [cls.finding(7, "vulnerable", "critical", "confirmed")],
            }
        )
        found.append(
            {
                "findings": [cls.finding(12, "malicious", "critical", "confirmed")],
                "revoked": True,
                "kill_listed": True,
                "integrity_ok": False,
                "complete": False,
            }
        )
        found.append({"revoked": True})
        found.append({"kill_listed": True})
        found.append({"integrity_ok": False})
        found.append(
            {"integrity_ok": True, "findings": [cls.finding(8, "suspicious", "low", "low")]}
        )
        found.append({"unresolved": True})
        found.append({"required_missing": ["provenance"]})
        found.append(
            {
                "required_missing": ["signature", "provenance"],
                "findings": [cls.finding(9, "policy", "low", "medium")],
            }
        )
        for level, signer, verified in (
            (0, None, False),
            (2, "builder-1", True),
            (3, "builder-2", True),
            (4, "builder-2", False),
        ):
            found.append(
                {"provenance": {"slsa_level": level, "signer": signer, "verified": verified}}
            )
        stamp = {"expires_at": "2026-12-01T00:00:00Z"}
        near = "@near"
        high = cls.finding(10, "suspicious", "high", "high")
        malicious = cls.finding(11, "malicious", "critical", "confirmed")
        found.append(
            {
                "findings": [malicious],
                "approvals": [
                    {
                        "id": "ap-1",
                        "kind": "approve",
                        "digests": [near],
                        "scope_path": ["acme"],
                        **stamp,
                    }
                ],
            }
        )
        found.append(
            {
                "findings": [high],
                "approvals": [
                    {
                        "id": "ap-2",
                        "kind": "approve_with_conditions",
                        "digests": [near],
                        "conditions": ["pin the digest"],
                        **stamp,
                    }
                ],
            }
        )
        found.append(
            {
                "findings": [high],
                "approvals": [
                    {
                        "id": "ex-1",
                        "kind": "exception",
                        "digests": [near],
                        "rule_ids": ["deny-high"],
                        "outcome": "REVIEW",
                        **stamp,
                    }
                ],
            }
        )
        found.append(
            {
                "findings": [high],
                "approvals": [{"id": "ex-2", "kind": "exception", "digests": [near], **stamp}],
            }
        )
        found.append(
            {
                "findings": [malicious],
                "approvals": [
                    {
                        "id": "ap-3",
                        "kind": "approve",
                        "digests": [near],
                        "expires_at": "2026-11-17T08:00:30Z",
                    }
                ],
            }
        )
        found.append(
            {
                "findings": [malicious],
                "approvals": [
                    {"id": "ap-4", "kind": "approve", "digests": [near], "revoked": True, **stamp}
                ],
            }
        )
        found.append(
            {
                "findings": [malicious],
                "approvals": [
                    {"id": "ap-5", "kind": "approve", "digests": ["sha256:" + "b" * 64], **stamp}
                ],
            }
        )
        found.append(
            {
                "findings": [malicious],
                "approvals": [
                    {
                        "id": "ap-6",
                        "kind": "approve",
                        "digests": [near],
                        "scope_path": ["acme", "other"],
                        **stamp,
                    }
                ],
            }
        )
        found.append(
            {
                "intel": [known],
                "approvals": [
                    {
                        "id": "ex-3",
                        "kind": "exception",
                        "digests": [near],
                        "reason_codes": ["R100"],
                        **stamp,
                    }
                ],
            }
        )
        found.append(
            {
                "intel": [known],
                "approvals": [{"id": "ap-7", "kind": "approve", "digests": [near], **stamp}],
            }
        )
        found.append(
            {
                "findings": [high],
                "gaps": [{"rule_id": "OPERATIONAL.SOURCE.UNPARSED"}],
                "approvals": [{"id": "ap-8", "kind": "approve", "digests": [near], **stamp}],
            }
        )
        found.append(
            {
                "findings": [malicious, high],
                "approvals": [
                    {
                        "id": "ex-4",
                        "kind": "exception",
                        "digests": [near],
                        "rule_ids": ["deny-malicious"],
                        "outcome": "ALLOW",
                        **stamp,
                    },
                    {
                        "id": "ap-9",
                        "kind": "approve_with_conditions",
                        "digests": [near],
                        "conditions": ["notify the owner"],
                        **stamp,
                    },
                ],
            }
        )
        found = found[:EVIDENCE]
        for index, item in enumerate(found):
            for approval in item.get("approvals", []):
                approval["digests"] = [
                    cls.digest(index % 12) if d == "@near" else d for d in approval["digests"]
                ]
        return found


class DecisionGoldens:
    """Builds the inputs, runs the cases, and tabulates the digests."""

    @classmethod
    def inputs(cls, golden_ids: list[dict[str, Any]]) -> dict[str, Any]:
        policies = Pools.policies()
        evidence = Pools.evidence()
        artifacts = Pools.artifacts(golden_ids)
        contexts = Pools.contexts()
        clocks = Pools.clocks()
        cases = [
            [
                p,
                e,
                (e + p % 3) % len(artifacts),
                (p * 3 + e * 7) % len(contexts),
                (p + e) % len(clocks),
            ]
            for p in range(len(policies))
            for e in range(len(evidence))
        ]
        return {
            "about": "decide() determinism goldens: tests/kits/decision_goldens.py; a case is [policy, evidence, artifact, context, clock] (indexes)",
            "policies": policies,
            "evidence": evidence,
            "artifacts": artifacts,
            "contexts": contexts,
            "clocks": clocks,
            "cases": cases,
        }

    @staticmethod
    def compile(chain: list[dict[str, Any]]) -> CompiledPolicy:
        """The sealed policy at the end of a chain (root first), each compiled under the ones before it."""
        compiled: list[CompiledPolicy] = []
        for source in chain:
            parents = tuple(item for item in compiled if item.id in source.get("extends", []))
            compiled.append(PolicyCompiler.compile(PolicySource.from_json(source), parents))
        return compiled[-1]

    @staticmethod
    def envelope(
        inputs: dict[str, Any], case: list[int], policy: CompiledPolicy, *, flipped: bool = False
    ) -> bytes:
        """The canonical bytes of the decision of one case. `flipped` reverses the findings' order first."""
        _policy_index, evidence_index, artifact_index, context_index, clock_index = case
        evidence = EvidenceSet.from_json(inputs["evidence"][evidence_index])
        if flipped:
            evidence = EvidenceSet.from_json(
                {
                    **inputs["evidence"][evidence_index],
                    "findings": list(
                        reversed(inputs["evidence"][evidence_index].get("findings", []))
                    ),
                }
            )
        decision = Decider.decide(
            ArtifactRef.from_json(inputs["artifacts"][artifact_index]),
            Context.from_json(inputs["contexts"][context_index]),
            policy,
            evidence,
            Instants.parse(inputs["clocks"][clock_index]),
        )
        return ArtifactDigests.canonical_json(decision.to_json())

    @classmethod
    def table(cls, inputs: dict[str, Any], cases_bytes: bytes) -> dict[str, Any]:
        policies = [cls.compile(item["chain"]) for item in inputs["policies"]]
        digests = [
            hashlib.sha256(cls.envelope(inputs, case, policies[case[0]])).hexdigest()
            for case in inputs["cases"]
        ]
        return {
            "about": "sha256 of the canonical decision/v1 predicate of every case in cases.json, in order",
            "cases_sha256": hashlib.sha256(cases_bytes).hexdigest(),
            "policies": [item.sha256 for item in policies],
            "envelopes": digests,
            "digest": hashlib.sha256("\n".join(digests).encode()).hexdigest(),
        }

    @classmethod
    def problems(cls, directory: Path) -> list[str]:
        """What differs between the committed goldens in `directory` and what this code computes from the committed inputs."""
        cases_bytes = (directory / CASES_FILE).read_bytes()
        recorded = json.loads((directory / ENVELOPES_FILE).read_text(encoding="utf-8"))
        found = cls.table(json.loads(cases_bytes), cases_bytes)
        problems: list[str] = []
        if found["cases_sha256"] != recorded["cases_sha256"]:
            problems.append("cases.json is not the file the envelopes were recorded from")
        for name in ("policies", "envelopes"):
            wrong = [
                index
                for index, (new, old) in enumerate(zip(found[name], recorded[name], strict=False))
                if new != old
            ]
            if wrong or len(found[name]) != len(recorded[name]):
                problems.append(
                    f"{name}: {len(wrong)} of {len(recorded[name])} differ (first at {wrong[:1]}), "
                    f"{len(found[name])} computed"
                )
        if found["digest"] != recorded["digest"]:
            problems.append("the digest over all the envelopes differs")
        return problems

    @classmethod
    def write(cls, directory: Path, golden_ids: list[dict[str, Any]]) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        inputs = cls.inputs(golden_ids)
        cases_bytes = (json.dumps(inputs, sort_keys=True, separators=(",", ":")) + "\n").encode()
        (directory / CASES_FILE).write_bytes(cases_bytes)
        table = cls.table(inputs, cases_bytes)
        (directory / ENVELOPES_FILE).write_text(
            json.dumps(table, sort_keys=True, indent=0) + "\n", encoding="utf-8"
        )
        counts = len(inputs["cases"])
        sys.stdout.write(
            f"{counts} cases, {len(table['policies'])} policies, digest {table['digest'][:16]}\n"
        )


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "write":
        ids = json.loads(Path(sys.argv[3]).read_text(encoding="utf-8"))
        DecisionGoldens.write(Path(sys.argv[2]), ids)
    elif len(sys.argv) == 3 and sys.argv[1] == "check":
        found = DecisionGoldens.problems(Path(sys.argv[2]))
        sys.stdout.write(f"{len(found)} problem(s)\n" + "".join(f"{item}\n" for item in found))
        raise SystemExit(1 if found else 0)
    else:
        sys.stderr.write(__doc__ or "")
        raise SystemExit(2)
