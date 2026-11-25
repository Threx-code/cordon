"""Inheritance (spec 6.2): a child may add and tighten; a child that weakens a mandatory parent is rejected,
with the exact field and the parent named. The rejection cases are generated: eight kinds of weakening x a
spread of values x two topologies (the child directly under the mandatory policy, and under a middle policy
that is not itself mandatory, so the lock must travel down the chain). Controls must compile."""

from __future__ import annotations

import copy
import itertools
from typing import Any, ClassVar

import pytest

from cordon_scanner.decide.decision.compiler import PolicyCompiler
from cordon_scanner.decide.decision.policy_source import PolicySource
from cordon_scanner.decide.decision.records import PolicyError

PARENT_RULES = [
    {
        "id": "deny-malicious",
        "tier": "deny",
        "then": "block",
        "when": {"finding.category": "malicious", "finding.confidence": ">=medium"},
    },
    {
        "id": "deny-critical",
        "tier": "deny",
        "then": "review",
        "when": {"finding.severity": ">=critical"},
    },
    {
        "id": "young-release",
        "tier": "require",
        "then": "review",
        "when": {"version.age_days": "<3d"},
    },
    {
        "id": "provenance-prod",
        "tier": "require",
        "then": "block",
        "applies_to": {"context.environment": "production"},
        "require": {"provenance.slsa_level": ">=2"},
    },
    {
        "id": "approved-mcp",
        "tier": "require",
        "then": "review",
        "applies_to": {"subject.kind": "mcp_server"},
        "require": {"approval": "present"},
    },
    {
        "id": "allow-internal",
        "tier": "allow",
        "then": "allow",
        "when": {"subject.namespace": {"in": "internal"}},
    },
]
CHILD_RULE_SHAPES = {
    "deny": [
        ("block", {"when": {"finding.category": "suspicious"}}),
        ("review", {"when": {"finding.category": "suspicious"}}),
    ],
    "require": [
        ("block", {"require": {"approval": "present"}, "reason": "R700"}),
        ("review", {"when": {"version.age_days": "<30d"}}),
    ],
    "allow": [
        ("allow", {"when": {"subject.namespace": "@acme"}}),
        ("allow_with_conditions", {"when": {"subject.namespace": "@acme"}}),
    ],
}


class Policies:
    PARENT_DEFAULTS: ClassVar[dict[str, Any]] = {
        "on_incomplete": {"*": "block", "production": "block"},
        "unresolved": "block",
        "default": "review",
        "max_intel_age": "7d",
        "bundle_max_age": "72h",
        "warn_until_measured": ["pypi"],
    }

    @classmethod
    def source(cls, id_: str, **kw: Any) -> PolicySource:
        return PolicySource.from_json({"policy_schema": 2, "id": id_, "version": 1, **kw})

    @classmethod
    def parent(cls, defaults: dict[str, Any] | None = None):
        return PolicyCompiler.compile(
            cls.source(
                "acme/baseline",
                mandatory=True,
                scope=["acme"],
                rules=copy.deepcopy(PARENT_RULES),
                lists={"internal": ["@acme"]},
                defaults=defaults or cls.PARENT_DEFAULTS,
            )
        )

    @classmethod
    def chain(cls, topology: str, parent_defaults: dict[str, Any] | None = None):
        """The policies a child sits under: the mandatory one, or the mandatory one and a middle one."""
        top = cls.parent(parent_defaults)
        if topology == "direct":
            return (top,)
        middle = PolicyCompiler.compile(
            cls.source("acme/team", scope=["acme", "payments"], extends=["acme/baseline"]), (top,)
        )
        return (middle,)

    @classmethod
    def child(cls, topology: str, parent_defaults: dict[str, Any] | None = None, **kw: Any):
        parents = cls.chain(topology, parent_defaults)
        scope = ["acme", "payments", "ledger"] if topology == "grandchild" else ["acme", "payments"]
        return PolicyCompiler.compile(
            cls.source("acme/ledger", scope=scope, extends=[parents[0].id], **kw), parents
        )


class Cases:
    """Every rejection case: (label, parent defaults or None, child fields, text the error must contain)."""

    @classmethod
    def rejections(cls) -> list[tuple[str, dict[str, Any] | None, dict[str, Any], str]]:
        cases: list[tuple[str, dict[str, Any] | None, dict[str, Any], str]] = []
        for rule, (tier, shapes) in itertools.product(PARENT_RULES, CHILD_RULE_SHAPES.items()):
            for then, extra in shapes:
                body = {"id": rule["id"], "tier": tier, "then": then, **extra}
                cases.append(
                    (
                        f"restate {rule['id']} as {tier}/{then}",
                        None,
                        {"rules": [body]},
                        f"rules.{rule['id']}",
                    )
                )
        for rule in PARENT_RULES:
            cases.append(
                (f"disable {rule['id']}", None, {"disable": [rule["id"]]}, f"disable.{rule['id']}")
            )
        levels = ("warn", "review", "block")
        for parent_level, env in itertools.product(("block", "review"), ("*", "production", "ci")):
            for child_level in levels[: levels.index(parent_level)]:
                parent = {
                    **Policies.PARENT_DEFAULTS,
                    "on_incomplete": {"*": parent_level, "production": parent_level},
                }
                cases.append(
                    (
                        f"on_incomplete {env} {parent_level}->{child_level}",
                        parent,
                        {"defaults": {"on_incomplete": {env: child_level}}},
                        f"defaults.on_incomplete.{env}",
                    )
                )
            parent = {**Policies.PARENT_DEFAULTS, "unresolved": parent_level}
        for parent_level in ("block", "review"):
            for child_level in levels[: levels.index(parent_level)]:
                parent = {**Policies.PARENT_DEFAULTS, "unresolved": parent_level}
                cases.append(
                    (
                        f"unresolved {parent_level}->{child_level}",
                        parent,
                        {"defaults": {"unresolved": child_level}},
                        "defaults.unresolved",
                    )
                )
        outcomes = ("allow", "allow_with_conditions", "review", "block")
        for parent_level in outcomes[1:]:
            for child_level in outcomes[: outcomes.index(parent_level)]:
                parent = {**Policies.PARENT_DEFAULTS, "default": parent_level}
                cases.append(
                    (
                        f"default {parent_level}->{child_level}",
                        parent,
                        {"defaults": {"default": child_level}},
                        "defaults.default",
                    )
                )
        for name in ("max_intel_age", "bundle_max_age", "exception_max_age"):
            for parent_age, child_age in itertools.product(
                ("1h", "1d", "72h", "7d"), ("2d", "30d", "8d", "100h", "none", 10_000_000)
            ):
                if child_age != "none" and cls._seconds(child_age) <= cls._seconds(parent_age):
                    continue
                parent = {**Policies.PARENT_DEFAULTS, name: parent_age}
                cases.append(
                    (
                        f"{name} {parent_age}->{child_age}",
                        parent,
                        {"defaults": {name: child_age}},
                        f"defaults.{name}",
                    )
                )
        for parent_level, child_level in (
            ("none", "review"),
            ("none", "allow"),
            ("review", "allow"),
        ):
            parent = {**Policies.PARENT_DEFAULTS, "exceptions": parent_level}
            cases.append(
                (
                    f"exceptions {parent_level}->{child_level}",
                    parent,
                    {"defaults": {"exceptions": child_level}},
                    "defaults.exceptions",
                )
            )
        for parent_list, added in itertools.product(
            ([], ["pypi"], ["pypi", "npm"]), ("npm", "cargo", "skills", "mcp", "go")
        ):
            if added in parent_list:
                continue
            parent = {**Policies.PARENT_DEFAULTS, "warn_until_measured": parent_list}
            cases.append(
                (
                    f"warn_until_measured {parent_list}+{added}",
                    parent,
                    {"defaults": {"warn_until_measured": [*parent_list, added]}},
                    "defaults.warn_until_measured",
                )
            )
        return cases

    @staticmethod
    def _seconds(value: Any) -> int:
        if isinstance(value, int):
            return value
        return int(value[:-1]) * {"h": 3600, "d": 86400}[value[-1]]

    @classmethod
    def controls(cls) -> list[tuple[str, dict[str, Any] | None, dict[str, Any]]]:
        """A child that adds or tightens: compiles."""
        return [
            (
                "adds a deny rule",
                None,
                {
                    "rules": [
                        {
                            "id": "own-deny",
                            "tier": "deny",
                            "then": "block",
                            "when": {"finding.category": "suspicious"},
                        }
                    ]
                },
            ),
            (
                "adds a require rule",
                None,
                {
                    "rules": [
                        {
                            "id": "own-require",
                            "tier": "require",
                            "then": "review",
                            "when": {"version.age_days": "<30d"},
                        }
                    ]
                },
            ),
            (
                "adds an allow rule",
                None,
                {
                    "rules": [
                        {
                            "id": "own-allow",
                            "tier": "allow",
                            "then": "allow",
                            "when": {"subject.namespace": "@acme"},
                        }
                    ]
                },
            ),
            ("states nothing", None, {}),
            ("on_incomplete same", None, {"defaults": {"on_incomplete": "block"}}),
            (
                "on_incomplete stricter for an environment",
                {**Policies.PARENT_DEFAULTS, "on_incomplete": {"*": "review"}},
                {"defaults": {"on_incomplete": {"production": "block"}}},
            ),
            (
                "on_incomplete raised everywhere",
                {**Policies.PARENT_DEFAULTS, "on_incomplete": {"*": "warn"}},
                {"defaults": {"on_incomplete": "block"}},
            ),
            (
                "unresolved stricter",
                {**Policies.PARENT_DEFAULTS, "unresolved": "review"},
                {"defaults": {"unresolved": "block"}},
            ),
            ("default stricter", None, {"defaults": {"default": "block"}}),
            ("default same", None, {"defaults": {"default": "review"}}),
            ("max_intel_age shorter", None, {"defaults": {"max_intel_age": "1d"}}),
            ("max_intel_age same", None, {"defaults": {"max_intel_age": "7d"}}),
            ("bundle_max_age shorter", None, {"defaults": {"bundle_max_age": "24h"}}),
            (
                "limit set where the parent has none",
                {**Policies.PARENT_DEFAULTS, "max_intel_age": None},
                {"defaults": {"max_intel_age": "30d"}},
            ),
            ("warn_until_measured shortened", None, {"defaults": {"warn_until_measured": []}}),
            ("warn_until_measured same", None, {"defaults": {"warn_until_measured": ["pypi"]}}),
            ("clock bucket changed", None, {"defaults": {"clock_bucket_s": 30}}),
            (
                "exceptions stricter",
                {**Policies.PARENT_DEFAULTS, "exceptions": "allow"},
                {"defaults": {"exceptions": "none"}},
            ),
            (
                "obligation on a new rule",
                None,
                {
                    "rules": [
                        {
                            "id": "own",
                            "tier": "deny",
                            "then": "review",
                            "when": {"finding.severity": ">=high"},
                            "obligations": ["O003"],
                        }
                    ]
                },
            ),
            ("a list of its own", None, {"lists": {"mine": ["x"]}}),
            (
                "several additions",
                None,
                {
                    "rules": [
                        {
                            "id": "a",
                            "tier": "deny",
                            "then": "block",
                            "when": {"finding.severity": "critical"},
                        },
                        {
                            "id": "b",
                            "tier": "allow",
                            "then": "allow",
                            "when": {"subject.tags": "internal"},
                        },
                    ],
                    "defaults": {"default": "block"},
                },
            ),
        ]


REJECTIONS = Cases.rejections()
CONTROLS = Cases.controls()


class TestAWeakeningChildIsRejected:
    def test_there_are_at_least_two_hundred_cases_and_twenty_controls(self) -> None:
        assert 2 * len(REJECTIONS) >= 200 and len(CONTROLS) >= 20

    @pytest.mark.parametrize("topology", ["direct", "grandchild"])
    @pytest.mark.parametrize(
        ("label", "parent_defaults", "child", "needle"),
        REJECTIONS,
        ids=[case[0] for case in REJECTIONS],
    )
    def test_the_field_and_the_mandatory_parent_are_named(
        self, topology, label, parent_defaults, child, needle
    ) -> None:
        with pytest.raises(PolicyError) as raised:
            Policies.child(topology, parent_defaults, **copy.deepcopy(child))
        message = str(raised.value)
        assert needle in message, label
        assert "acme/baseline" in message or "mandatory" in message, label


class TestAChildThatAddsOrTightensCompiles:
    @pytest.mark.parametrize("topology", ["direct", "grandchild"])
    @pytest.mark.parametrize(
        ("label", "parent_defaults", "child"), CONTROLS, ids=[case[0] for case in CONTROLS]
    )
    def test_it_compiles_and_keeps_every_parent_rule(
        self, topology, label, parent_defaults, child
    ) -> None:
        policy = Policies.child(topology, parent_defaults, **copy.deepcopy(child))
        ids = [rule.id for rule in policy.rules]
        assert all(rule["id"] in ids for rule in PARENT_RULES), label
        assert policy.locked_by == ("acme/baseline",)
        assert all(
            rule.mandatory for rule in policy.rules if rule.id in {r["id"] for r in PARENT_RULES}
        )


class TestWithoutAMandatoryParentAChildMayOverride:
    def parent(self) -> Any:
        return PolicyCompiler.compile(
            Policies.source(
                "org/base",
                scope=["org"],
                rules=copy.deepcopy(PARENT_RULES),
                lists={"internal": ["@acme"]},
                defaults=Policies.PARENT_DEFAULTS,
            )
        )

    def test_it_can_replace_a_rule_disable_one_and_loosen_a_default(self) -> None:
        parent = self.parent()
        child = PolicyCompiler.compile(
            Policies.source(
                "org/team",
                scope=["org", "team"],
                extends=["org/base"],
                rules=[
                    {
                        "id": "young-release",
                        "tier": "require",
                        "then": "review",
                        "when": {"version.age_days": "<1d"},
                    }
                ],
                disable=["approved-mcp"],
                defaults={"default": "allow", "max_intel_age": "30d", "on_incomplete": "warn"},
            ),
            (parent,),
        )
        by_id = {rule.id: rule for rule in child.rules}
        assert "approved-mcp" not in by_id and by_id["young-release"].origin == "org/team"
        assert child.defaults.default == "allow" and child.defaults.max_intel_age_s == 30 * 86400
        assert child.locked_by == ()


class TestTheChainItself:
    def test_a_child_outside_its_parents_scope_or_with_other_parents_is_refused(self) -> None:
        (parent,) = Policies.chain("direct")
        with pytest.raises(PolicyError, match="scope"):
            PolicyCompiler.compile(
                Policies.source("x", scope=["other"], extends=["acme/baseline"]), (parent,)
            )
        with pytest.raises(PolicyError, match="extends"):
            PolicyCompiler.compile(Policies.source("x", scope=["acme"], extends=[]), (parent,))

    def test_a_parent_whose_table_was_edited_is_not_inherited(self) -> None:
        (parent,) = Policies.chain("direct")
        shape = parent.to_json()
        shape["rules"][0]["then"] = "allow"
        from cordon_scanner.decide.decision.table import CompiledPolicy

        with pytest.raises(PolicyError, match="digest"):
            PolicyCompiler.compile(
                Policies.source("x", scope=["acme"], extends=["acme/baseline"]),
                (CompiledPolicy.from_json(shape),),
            )

    def test_two_parents_give_the_stricter_defaults(self) -> None:
        strict = PolicyCompiler.compile(
            Policies.source("a", scope=["o"], defaults={"max_intel_age": "1d", "default": "block"})
        )
        loose = PolicyCompiler.compile(
            Policies.source(
                "b",
                scope=["o"],
                defaults={"max_intel_age": "7d", "default": "allow", "on_incomplete": "warn"},
            )
        )
        child = PolicyCompiler.compile(
            Policies.source("c", scope=["o", "p"], extends=["a", "b"]), (strict, loose)
        )
        assert child.defaults.max_intel_age_s == 86400 and child.defaults.default == "block"
        assert child.defaults.incomplete_for("production") == "block"
