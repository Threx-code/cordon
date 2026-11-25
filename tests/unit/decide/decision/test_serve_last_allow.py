"""The policy default `defaults.degrade.serve_last_allow_hours`: how long an earlier ALLOW may stand in for a decision held back by facts that cannot be had.

Default 24 hours, at most 168, 0 off; compiled into the bundle; a child under a mandatory parent may shorten it and never lengthen it;
a policy that does not state it compiles to the same bytes as before (the field is absent, not 24).
"""

from __future__ import annotations

import pytest

from cordon_scanner.decide.decision.compiler import PolicyCompiler
from cordon_scanner.decide.decision.policy_source import PolicySource
from cordon_scanner.decide.decision.records import DecisionError, PolicyError


class Make:
    @staticmethod
    def source(
        id_: str,
        hours: int | None = None,
        *,
        mandatory: bool = False,
        extends: tuple[str, ...] = (),
        scope=("acme",),
    ):
        defaults: dict = {} if hours is None else {"degrade": {"serve_last_allow_hours": hours}}
        return PolicySource.from_json(
            {
                "policy_schema": 2,
                "id": id_,
                "version": 1,
                "scope": list(scope),
                "rules": [],
                "defaults": defaults,
                "mandatory": mandatory,
                "extends": list(extends),
            }
        )

    @classmethod
    def compiled(cls, id_: str, hours: int | None = None, parents=(), **more):
        return PolicyCompiler.compile(cls.source(id_, hours, **more), parents)


class TestTheDefault:
    def test_nothing_stated_is_24_hours_and_the_compiled_policy_does_not_say_so(self) -> None:
        policy = Make.compiled("acme/base")
        assert policy.defaults.serve_last_allow_seconds() == 86_400
        assert "serve_last_allow_s" not in policy.to_json()["defaults"]

    def test_what_is_stated_is_kept_in_seconds_and_in_the_digest(self) -> None:
        shorter, longer = Make.compiled("acme/a", 6), Make.compiled("acme/a", 48)
        assert shorter.defaults.serve_last_allow_seconds() == 6 * 3600
        assert longer.defaults.serve_last_allow_seconds() == 48 * 3600
        assert shorter.sha256 != longer.sha256 != Make.compiled("acme/a").sha256

    def test_zero_is_off_and_168_is_the_most(self) -> None:
        assert Make.compiled("acme/a", 0).defaults.serve_last_allow_seconds() == 0
        assert Make.compiled("acme/a", 168).defaults.serve_last_allow_seconds() == 168 * 3600

    @pytest.mark.parametrize("hours", [169, 1000, -1])
    def test_more_than_168_hours_or_a_negative_number_is_refused(self, hours: int) -> None:
        with pytest.raises(DecisionError):
            Make.source("acme/a", hours)


class TestInheritance:
    def test_a_child_under_a_mandatory_parent_may_shorten_it(self) -> None:
        parent = Make.compiled("org/root", 24, mandatory=True, scope=())
        child = Make.compiled("acme/team", 6, parents=(parent,), extends=("org/root",))
        assert child.defaults.serve_last_allow_seconds() == 6 * 3600

    @pytest.mark.parametrize("parent_hours", [24, None])
    def test_a_child_under_a_mandatory_parent_may_not_lengthen_it(
        self, parent_hours: int | None
    ) -> None:
        parent = Make.compiled("org/root", parent_hours, mandatory=True, scope=())
        with pytest.raises(PolicyError, match="serve_last_allow_hours"):
            Make.compiled("acme/team", 48, parents=(parent,), extends=("org/root",))

    def test_a_child_that_is_not_under_a_mandatory_parent_may_lengthen_it(self) -> None:
        parent = Make.compiled("org/root", 24, scope=())
        child = Make.compiled("acme/team", 100, parents=(parent,), extends=("org/root",))
        assert child.defaults.serve_last_allow_seconds() == 100 * 3600

    def test_a_child_that_states_nothing_inherits(self) -> None:
        parent = Make.compiled("org/root", 6, scope=())
        child = Make.compiled("acme/team", None, parents=(parent,), extends=("org/root",))
        assert child.defaults.serve_last_allow_seconds() == 6 * 3600

    def test_two_parents_give_the_shorter_window_an_unstated_one_being_24_hours(self) -> None:
        one, two = Make.compiled("org/a", 100, scope=()), Make.compiled("org/b", None, scope=())
        child = Make.compiled("acme/team", None, parents=(one, two), extends=("org/a", "org/b"))
        assert child.defaults.serve_last_allow_seconds() == 24 * 3600
