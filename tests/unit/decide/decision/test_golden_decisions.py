"""`decide()` is deterministic: the same inputs give a byte-identical decision on every machine (design spec 21.2, M1 acceptance (a)).

`golden/cases.json` holds 2,000 fixed cases (40 policies x 50 evidence sets, each with its artifact, context and clock) built from
repository fixtures only, and `golden/envelopes.json` the sha256 of the canonical `decision/v1` predicate of each, one digest over
all of them, and the digest of `cases.json`. These tests recompute and compare; the pull request's CI runs them on three operating
systems and five Pythons, which is the cross-platform proof. A change to any decision is a diff in `envelopes.json`, reviewed:
`python tests/kits/decision_goldens.py write tests/unit/decide/decision/golden tests/unit/contracts/golden_ids.json`.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from functools import cache
from pathlib import Path
from typing import Any, ClassVar

import pytest

from cordon_scanner.decide.decision.decider import Decider
from cordon_scanner.decide.decision.evidence import ArtifactRef, Context, EvidenceSet
from cordon_scanner.decide.decision.outcome import Decision, States
from cordon_scanner.decide.decision.records import DecisionError, Instants
from kits.decision_goldens import CASES_FILE, ENVELOPES_FILE, DecisionGoldens
from support import ROOT

GOLDEN = ROOT / "tests" / "unit" / "decide" / "decision" / "golden"
KIT = ROOT / "tests" / "kits" / "decision_goldens.py"


class Computed:
    """The committed inputs, the policies compiled from them, and every case decided once."""

    @staticmethod
    @cache
    def inputs() -> dict[str, Any]:
        loaded: dict[str, Any] = json.loads((GOLDEN / CASES_FILE).read_bytes())
        return loaded

    @staticmethod
    @cache
    def recorded() -> dict[str, Any]:
        loaded: dict[str, Any] = json.loads((GOLDEN / ENVELOPES_FILE).read_text(encoding="utf-8"))
        return loaded

    @classmethod
    @cache
    def policies(cls) -> list[Any]:
        return [DecisionGoldens.compile(item["chain"]) for item in cls.inputs()["policies"]]

    @classmethod
    @cache
    def decisions(cls) -> list[dict[str, Any]]:
        """Each case's decision as a plain document."""
        inputs = cls.inputs()
        policies = cls.policies()
        return [
            json.loads(DecisionGoldens.envelope(inputs, case, policies[case[0]]))
            for case in inputs["cases"]
        ]


class TestTheRecordedDigests:
    def test_the_inputs_are_the_file_the_digests_were_recorded_from(self) -> None:
        assert (
            hashlib.sha256((GOLDEN / CASES_FILE).read_bytes()).hexdigest()
            == Computed.recorded()["cases_sha256"]
        )

    def test_every_policy_compiles_to_its_recorded_digest(self) -> None:
        assert [policy.sha256 for policy in Computed.policies()] == Computed.recorded()["policies"]

    def test_every_case_gives_its_recorded_envelope_and_all_of_them_the_recorded_digest(
        self,
    ) -> None:
        assert DecisionGoldens.problems(GOLDEN) == []

    def test_a_changed_decision_is_found(self, tmp_path: Path) -> None:
        recorded = dict(Computed.recorded())
        recorded["envelopes"] = [recorded["envelopes"][0][::-1], *recorded["envelopes"][1:]]
        (tmp_path / CASES_FILE).write_bytes((GOLDEN / CASES_FILE).read_bytes())
        (tmp_path / ENVELOPES_FILE).write_text(json.dumps(recorded), encoding="utf-8")
        found = DecisionGoldens.problems(tmp_path)
        assert any("envelopes: 1 of 2000 differ" in line for line in found)
        assert "the digest over all the envelopes differs" not in found


class TestTheCasesAreNotTrivial:
    def test_two_thousand_cases_with_every_state_and_many_reasons(self) -> None:
        decisions = Computed.decisions()
        assert len(decisions) == 2000
        states = {item["state"] for item in decisions}
        assert {"ALLOW", "REVIEW", "BLOCK", "ALLOW_WITH_CONDITIONS"} <= states
        reasons = {code for item in decisions for code in item["reason_codes"]}
        assert {
            "R100",
            "R101",
            "R102",
            "R103",
            "R200",
            "R201",
            "R202",
            "R204",
            "R400",
            "R702",
        } <= reasons
        assert len(reasons) >= 20
        obligations = {code for item in decisions for code in item.get("obligations", [])}
        assert obligations

    def test_the_policies_are_the_kinds_the_design_names(self) -> None:
        names = [item["name"] for item in Computed.inputs()["policies"]]
        kinds = {name.split("-", 1)[0] for name in names}
        assert {"legacy", "v2", "chain", "allow"} <= kinds
        assert len(names) == 40 and len(set(Computed.recorded()["policies"])) == 40


class TestNothingAroundTheCallChangesTheBytes:
    def test_findings_in_the_reverse_order_give_the_same_decision(self) -> None:
        inputs, policies = Computed.inputs(), Computed.policies()
        for number, case in enumerate(inputs["cases"]):
            if number % 7:
                continue
            same = DecisionGoldens.envelope(inputs, case, policies[case[0]], flipped=True)
            assert same == DecisionGoldens.envelope(inputs, case, policies[case[0]]), number

    def test_the_json_entry_gives_the_same_decision_as_the_call(self) -> None:
        inputs, policies = Computed.inputs(), Computed.policies()
        taken = refused = 0
        for number, case in enumerate(inputs["cases"]):
            if number % 25:
                continue
            policy_index, evidence_index, artifact_index, context_index, clock_index = case
            request = {
                "artifact": inputs["artifacts"][artifact_index],
                "context": inputs["contexts"][context_index],
                "policy": policies[policy_index].to_json(),
                "evidence": inputs["evidence"][evidence_index],
                "clock": inputs["clocks"][clock_index],
            }
            if EvidenceSet.from_json(request["evidence"]).request_problems():
                with pytest.raises(DecisionError):
                    Decider.decide_json(request)
                refused += 1
                continue
            assert Decider.decide_json(request) == Computed.decisions()[number]
            taken += 1
        assert taken >= 70

    @pytest.mark.parametrize(("seed", "locale"), [("1", "C"), ("4242", "C.UTF-8"), ("random", "C")])
    def test_another_hash_seed_or_locale_gives_the_recorded_digests(
        self, seed: str, locale: str
    ) -> None:
        """A separate interpreter, so the seed and the locale really change: set order and string hashing must not reach the output."""
        environment = {**os.environ, "PYTHONHASHSEED": seed, "LC_ALL": locale, "LANG": locale}
        done = subprocess.run(
            [sys.executable, str(KIT), "check", str(GOLDEN)],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        assert done.returncode == 0, done.stdout + done.stderr


class Variants:
    """The golden policies with one rule added, and the golden cases decided under them."""

    ALLOW_EVERYTHING: ClassVar[dict[str, Any]] = {
        "id": "prop-allow-all",
        "tier": "allow",
        "then": "allow",
    }
    BLOCK_ANY_FINDING: ClassVar[dict[str, Any]] = {
        "id": "prop-deny-any",
        "tier": "deny",
        "then": "block",
        "when": {"finding.severity": ">=info"},
    }

    @staticmethod
    @cache
    def policy(index: int, rule: str) -> Any:
        chain = json.loads(json.dumps(Computed.inputs()["policies"][index]["chain"]))
        chain[-1]["rules"] = [*chain[-1].get("rules", []), json.loads(rule)]
        return DecisionGoldens.compile(chain)

    @classmethod
    def decide(
        cls, case: list[int], *, rule: dict[str, Any] | None = None, approvals: bool = True
    ) -> Decision:
        inputs = Computed.inputs()
        policy_index, evidence_index, artifact_index, context_index, clock_index = case
        policy = (
            Computed.policies()[policy_index]
            if rule is None
            else cls.policy(policy_index, json.dumps(rule, sort_keys=True))
        )
        evidence = dict(inputs["evidence"][evidence_index])
        if not approvals:
            evidence["approvals"] = []
        return Decider.decide(
            ArtifactRef.from_json(inputs["artifacts"][artifact_index]),
            Context.from_json(inputs["contexts"][context_index]),
            policy,
            EvidenceSet.from_json(evidence),
            Instants.parse(inputs["clocks"][clock_index]),
        )

    @classmethod
    def sample(cls, step: int = 3) -> list[list[int]]:
        return Computed.inputs()["cases"][::step]

    @staticmethod
    def has_approvals(case: list[int]) -> bool:
        return bool(Computed.inputs()["evidence"][case[1]].get("approvals"))


class TestPropertiesOverTheGoldenCases:
    """The design note's properties (reviews/platform/10, section 6), held on a third of the golden cases."""

    def test_an_allow_rule_never_weakens_a_block_that_a_rule_or_a_stop_gave(self) -> None:
        checked = 0
        for case in Variants.sample():
            before = Variants.decide(case)
            # A policy's default is not a rule: an allow rule is an allowlist and does replace a default block.
            if before.state != "BLOCK" or before.reason_codes == ("R700",):
                continue
            assert Variants.decide(case, rule=Variants.ALLOW_EVERYTHING).state == "BLOCK", case
            checked += 1
        assert checked >= 100

    def test_a_deny_rule_never_weakens_a_decision_where_no_approval_is_in_play(self) -> None:
        checked = 0
        for case in Variants.sample():
            if Variants.has_approvals(case):
                continue
            before = Variants.decide(case)
            after = Variants.decide(case, rule=Variants.BLOCK_ANY_FINDING)
            assert States.rank(after.state) >= States.rank(before.state), case
            checked += 1
        assert checked >= 250

    def test_removing_approvals_never_weakens_a_decision_and_sometimes_strengthens_it(self) -> None:
        stronger = checked = 0
        for case in Variants.sample(1):
            if not Variants.has_approvals(case):
                continue
            kept = Variants.decide(case)
            dropped = Variants.decide(case, approvals=False)
            assert States.rank(dropped.state) >= States.rank(kept.state), case
            stronger += States.rank(dropped.state) > States.rank(kept.state)
            checked += 1
        assert checked >= 400 and stronger >= 20

    def test_an_approval_never_reaches_a_hard_stop(self) -> None:
        stops = ("R100", "R101", "R102", "R103")
        checked = 0
        for case in Variants.sample(1):
            without = Variants.decide(case, approvals=False)
            if not any(code in stops for code in without.reason_codes):
                continue
            assert Variants.decide(case).state == "BLOCK", case
            checked += 1
        assert checked >= 100


BRIDGE = "legacy.py"
"""The harness that runs `PolicyGate` and `decide()` on one pair to compare them: it may default a missing day to today, and the decision function never imports it."""
LIBRARY = sorted(
    p
    for p in (ROOT / "src" / "cordon_scanner" / "decide" / "decision").glob("*.py")
    if p.name != BRIDGE
)


class Reaches:
    """What `decide()` and the modules around it must never reach: a file, the network, a process, the clock, the environment or a source of chance."""

    MODULES: ClassVar[frozenset[str]] = frozenset(
        {"os", "sys", "time", "socket", "ssl", "subprocess", "urllib", "http", "shutil", "tempfile", "pathlib", "io", "random", "secrets", "uuid", "logging", "threading", "multiprocessing", "sqlite3", "glob"}
    )  # fmt: skip
    CALLS: ClassVar[frozenset[str]] = frozenset(
        {"open", "input", "print", "exec", "eval", "__import__"}
    )
    ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
        {"now", "utcnow", "today", "getenv", "environ", "monotonic", "perf_counter"}
    )

    @classmethod
    def imports(cls, path: Path) -> list[str]:
        import ast

        found = []
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else []
            if isinstance(node, ast.ImportFrom) and node.module and not node.level:
                names = [node.module]
            found += [f"{path.name}: imports {n}" for n in names if n.split(".")[0] in cls.MODULES]
        return found

    @classmethod
    def calls(cls, path: Path) -> list[str]:
        import ast

        found = []
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in cls.CALLS
            ):
                found.append(f"{path.name}:{node.lineno} calls {node.func.id}")
            if isinstance(node, ast.Attribute) and node.attr in cls.ATTRIBUTES:
                found.append(f"{path.name}:{node.lineno} reads .{node.attr}")
        return found


class Tripwire(dict[str, str]):
    """An environment that fails when anything reads it."""

    def __getitem__(self, key: str) -> str:
        raise AssertionError("decide() read the environment")

    def get(self, key: str, default: Any = None) -> Any:
        raise AssertionError("decide() read the environment")


class TestNothingIsReachedInsideDecide:
    """The library has no I/O, clock or environment access (an import and call audit), and a decision made with every such door shut is the decision made with them open."""

    def test_the_library_has_modules_to_audit(self) -> None:
        assert len(LIBRARY) >= 10 and any(p.name == "decider.py" for p in LIBRARY)

    def test_nothing_in_the_library_imports_the_comparison_harness(self) -> None:
        text = [p.read_text(encoding="utf-8") for p in LIBRARY]
        assert not [t for t in text if "decision.legacy" in t or "import legacy" in t]

    def test_no_module_imports_a_file_network_process_clock_or_chance_module(self) -> None:
        assert [line for path in LIBRARY for line in Reaches.imports(path)] == []

    def test_no_module_opens_a_file_or_reads_the_clock_or_the_environment(self) -> None:
        assert [line for path in LIBRARY for line in Reaches.calls(path)] == []

    def test_a_hundred_cases_are_decided_the_same_with_every_door_shut(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import builtins
        import socket
        import time

        inputs, policies = Computed.inputs(), Computed.policies()
        expected = Computed.decisions()[:100]

        def shut(*args: object, **kwargs: object) -> Any:
            raise AssertionError("decide() reached outside itself")

        for target, name in (
            (builtins, "open"),
            (socket, "socket"),
            (time, "time"),
            (time, "monotonic"),
            (time, "perf_counter"),
            (os, "getenv"),
            (subprocess, "run"),
            (subprocess, "Popen"),
        ):
            monkeypatch.setattr(target, name, shut)
        monkeypatch.setattr(os, "environ", Tripwire())
        shut_decisions = [
            json.loads(DecisionGoldens.envelope(inputs, case, policies[case[0]]))
            for case in inputs["cases"][:100]
        ]
        assert shut_decisions == expected
