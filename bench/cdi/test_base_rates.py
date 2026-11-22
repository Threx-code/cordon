"""A class with a high base rate on established legitimate packages cannot make a malicious label alone."""

from __future__ import annotations

from bench.cdi.base_rates import CEILING, MIN_LEGIT, BaseRates


class TestTheBaseRates:
    def table(self) -> dict:
        return BaseRates.table(
            {
                "reads-environment": (1_400, 5_000),  # common: 28% of legitimate packages
                "install-time-network": (180, 5_000),  # still above the ceiling
                "reads-ssh-keys": (0, 5_000),  # none among five thousand
                "writes-outside-package": (0, 20),  # none, but counted on too few to believe
                "rare-but-seen": (30, 5_000),  # 0.6%: the interval reaches above the ceiling
            }
        )

    def test_each_class_has_its_rate_and_interval(self) -> None:
        rate = self.table()["reads-environment"]["rate"]
        assert (rate["k"], rate["n"], rate["value"]) == (1_400, 5_000, 0.28) and rate[
            "low"
        ] < 0.28 < rate["high"]

    def test_a_class_with_a_high_base_rate_cannot_make_a_malicious_label_alone(self) -> None:
        table = self.table()
        assert table["reads-environment"]["may_label_alone"] is False
        assert BaseRates.label(["reads-environment"], table, other_evidence=False) is False

    def test_a_class_none_of_five_thousand_legitimate_packages_show_may(self) -> None:
        table = self.table()
        assert table["reads-ssh-keys"]["rate"]["high"] <= CEILING
        assert BaseRates.label(["reads-ssh-keys"], table, other_evidence=False) is True

    def test_a_class_counted_on_too_few_packages_may_not_label_alone_even_at_zero(self) -> None:
        assert MIN_LEGIT > 20
        assert self.table()["writes-outside-package"]["may_label_alone"] is False

    def test_a_class_whose_interval_reaches_above_the_ceiling_may_not(self) -> None:
        assert self.table()["rare-but-seen"]["rate"]["high"] > CEILING
        assert self.table()["rare-but-seen"]["may_label_alone"] is False

    def test_a_common_class_beside_independent_evidence_may_support_a_label(self) -> None:
        assert BaseRates.label(["reads-environment"], self.table(), other_evidence=True) is True

    def test_no_class_at_all_labels_nothing_and_an_unknown_class_has_no_base_rate(self) -> None:
        assert BaseRates.label([], self.table(), other_evidence=True) is False
        assert BaseRates.label(["never-measured"], self.table(), other_evidence=False) is False

    def test_a_class_counted_on_no_package_has_no_rate_not_a_zero(self) -> None:
        assert BaseRates.table({"x": (0, 0)})["x"] == {"rate": None, "may_label_alone": False}

    def test_the_ceiling_is_the_gates_own_benign_bar(self) -> None:
        from bench.cdi.gate import DEFAULT_POLICY

        assert (
            DEFAULT_POLICY["benign_ub_bar"] == CEILING
            and DEFAULT_POLICY["min_benign_n_for_bar"] == MIN_LEGIT
        )
