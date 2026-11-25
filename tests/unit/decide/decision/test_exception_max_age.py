"""A policy may set the longest an approval or exception can be granted for (`defaults.exception_max_age`): it compiles
to seconds, a child may shorten it but never lengthen or drop it under a mandatory parent, and of two parents the
shorter limit holds. The platform refuses a request for longer than the active policy allows."""

from __future__ import annotations

import pytest
from tests.unit.decide.decision.test_inheritance import Policies

from cordon_scanner.decide.decision.compiler import PolicyCompiler
from cordon_scanner.decide.decision.merge import DefaultsMerge
from cordon_scanner.decide.decision.records import PolicyError
from cordon_scanner.decide.decision.table import Defaults


class TestTheLimit:
    def test_it_compiles_to_seconds(self) -> None:
        compiled = Policies.parent({**Policies.PARENT_DEFAULTS, "exception_max_age": "30d"})
        assert compiled.defaults.exception_max_age_s == 30 * 86_400

    def test_unset_it_leaves_the_platforms_own_limit(self) -> None:
        assert Policies.parent().defaults.exception_max_age_s is None

    def test_a_child_may_shorten_it(self) -> None:
        parent = {**Policies.PARENT_DEFAULTS, "exception_max_age": "30d"}
        child = Policies.child("direct", parent, defaults={"exception_max_age": "7d"})
        assert child.defaults.exception_max_age_s == 7 * 86_400

    @pytest.mark.parametrize("longer", ["31d", "none"])
    def test_a_child_cannot_lengthen_or_drop_it_under_a_mandatory_parent(self, longer) -> None:
        parent = {**Policies.PARENT_DEFAULTS, "exception_max_age": "30d"}
        with pytest.raises(PolicyError, match=r"defaults\.exception_max_age"):
            Policies.child("direct", parent, defaults={"exception_max_age": longer})

    def test_of_two_parents_the_shorter_holds(self) -> None:
        one = PolicyCompiler.compile(
            Policies.source(
                "acme/a", mandatory=True, scope=["acme"], defaults={"exception_max_age": "14d"}
            )
        )
        two = PolicyCompiler.compile(
            Policies.source(
                "acme/b", mandatory=True, scope=["acme"], defaults={"exception_max_age": "60d"}
            )
        )
        assert DefaultsMerge._parents([one, two]).exception_max_age_s == 14 * 86_400

    def test_the_compiled_defaults_carry_it(self) -> None:
        assert "exception_max_age_s" in Defaults.__dataclass_fields__
