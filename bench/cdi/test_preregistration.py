"""Thresholds are written down in code before any number is seen, and a change after a recorded number is refused."""

from __future__ import annotations

from pathlib import Path

import pytest
from bench.cdi.gate import DEFAULT_POLICY, Gate
from bench.cdi.preregistration import REGISTERED, Preregistration, ThresholdChanged
from bench.cdi.test_gate import BEN_CLEAN, MAL, GateKit


class TestTheRegisteredPolicy:
    def test_the_default_policy_is_exactly_what_was_registered_for_its_id(self) -> None:
        assert REGISTERED[DEFAULT_POLICY["policy_id"]] == Preregistration.digest(DEFAULT_POLICY)

    def test_every_registered_id_is_a_policy_id_and_every_digest_is_sha256(self) -> None:
        assert all(
            key and len(value) == 64 and set(value) <= set("0123456789abcdef")
            for key, value in REGISTERED.items()
        )

    def test_an_edit_to_one_threshold_changes_the_digest(self) -> None:
        for key, value in DEFAULT_POLICY.items():
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                assert (
                    Preregistration.digest({**DEFAULT_POLICY, key: value + 1})
                    != REGISTERED[DEFAULT_POLICY["policy_id"]]
                ), key


class TestTheGateRefusesAChangedThreshold:
    def spec(self, tmp_path: Path, **extra) -> dict:
        return GateKit.spec(
            tmp_path, {"m1": (1, MAL, 1.0), "m2": (1, MAL, 1.0)}, BEN_CLEAN, **extra
        )

    def test_a_number_is_recorded_under_the_registered_policy(self, tmp_path: Path) -> None:
        _, decision = Gate.evaluate(self.spec(tmp_path))
        assert decision["outcome"] == "shadow"

    def test_the_same_policy_id_with_a_looser_bar_after_that_number_is_refused(
        self, tmp_path: Path
    ) -> None:
        Gate.evaluate(self.spec(tmp_path))
        looser = {
            "policy_id": DEFAULT_POLICY["policy_id"],
            "benign_ub_bar": DEFAULT_POLICY["benign_ub_bar"] * 4,
        }
        with pytest.raises(ThresholdChanged, match="benign_ub_bar"):
            Gate.evaluate(self.spec(tmp_path, policy=looser))

    def test_an_allowance_for_new_benign_blocks_is_a_change_too(self, tmp_path: Path) -> None:
        with pytest.raises(ThresholdChanged):
            Gate.evaluate(self.spec(tmp_path, policy={"allow_new_benign_blocks": 3}))

    def test_a_policy_with_an_id_nobody_registered_is_refused(self, tmp_path: Path) -> None:
        with pytest.raises(ThresholdChanged, match="not pre-registered"):
            Gate.evaluate(self.spec(tmp_path, policy={"policy_id": "gate-policy/9"}))

    def test_a_policy_with_no_id_is_refused(self) -> None:
        with pytest.raises(ThresholdChanged):
            Preregistration.check({"lose_max": 0})

    def test_a_policy_restated_with_the_same_values_is_accepted(self, tmp_path: Path) -> None:
        _, decision = Gate.evaluate(self.spec(tmp_path, policy=dict(DEFAULT_POLICY)))
        assert decision["outcome"] == "shadow"
