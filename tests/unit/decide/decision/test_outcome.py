"""The decision records: states, registered reason codes, and the decision/v1 shape."""

from __future__ import annotations

import pytest

from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.contracts.schema_check import SchemaChecker
from cordon_scanner.contracts.schemas import ContractSchemas
from cordon_scanner.decide.decision.outcome import (
    Decision,
    DecisionContext,
    Explanation,
    PolicyRef,
    Reason,
    States,
)
from cordon_scanner.decide.decision.records import DecisionError

DIGEST = ArtifactDigests.of_bytes(b"policy")


class Samples:
    @staticmethod
    def decision(**kw) -> Decision:
        reason = Reason(
            "R400",
            "an install script downloads a file and runs it",
            rule_id="MALWARE.DROPPER.001",
            path="install.js",
            line=12,
        )
        return Decision(
            state=kw.pop("state", "BLOCK"),
            reason_codes=kw.pop("reason_codes", ("R400",)),
            explanation=Explanation("blocked", (reason,)),
            obligations=(),
            inputs_digest=ArtifactDigests.of_bytes(b"inputs"),
            policy=PolicyRef("acme/production", 14, DIGEST),
            context=DecisionContext("cli", "production", "direct"),
            clock_bucket="2026-11-17T08:00:00Z",
            **kw,
        )


decision = Samples.decision


class TestStates:
    def test_block_is_the_strictest_and_allow_the_laxest(self) -> None:
        assert [States.rank(s) for s in States.ORDER] == [0, 1, 2, 3]
        assert States.stricter("REVIEW", "ALLOW_WITH_CONDITIONS") == "REVIEW"
        assert States.stricter("ALLOW", "BLOCK") == "BLOCK"
        assert States.stricter("REVIEW", "REVIEW") == "REVIEW"


class TestADecision:
    def test_it_is_a_valid_decision_v1_predicate(self) -> None:
        shape = decision().to_json()
        assert SchemaChecker.errors(ContractSchemas.load("decision-v1"), shape) == []

    def test_it_round_trips(self) -> None:
        assert Decision.from_json(decision().to_json()) == decision()

    @pytest.mark.parametrize(
        "kw",
        [
            {"state": "DENY"},
            {"reason_codes": ()},
            {"reason_codes": ("R400", "R400")},
        ],
    )
    def test_a_malformed_decision_is_refused(self, kw) -> None:
        with pytest.raises(DecisionError):
            decision(**kw)

    def test_a_reason_must_be_a_registered_code(self) -> None:
        with pytest.raises(DecisionError):
            Reason("R999", "unknown")

    def test_the_canonical_bytes_are_stable(self) -> None:
        assert decision().canonical_bytes() == decision().canonical_bytes()
        assert decision().blocked and not decision(state="REVIEW").blocked
