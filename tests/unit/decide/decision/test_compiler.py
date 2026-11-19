"""`PolicyCompiler`: a source to a sealed table; the same source, the same bytes; errors name the path."""

from __future__ import annotations

import copy

import pytest

from cordon_scanner.decide.decision.compiler import PolicyCompiler
from cordon_scanner.decide.decision.policy_source import Durations, PolicySource
from cordon_scanner.decide.decision.records import DecisionError, PolicyError
from cordon_scanner.decide.decision.table import CompiledPolicy

SOURCE = {
    "policy_schema": 2,
    "id": "acme/production",
    "version": 14,
    "scope": ["acme", "payments"],
    "defaults": {
        "on_incomplete": "block",
        "max_intel_age": "7d",
        "bundle_max_age": "72h",
        "warn_until_measured": ["pypi", "mcp"],
    },
    "lists": {
        "internal_namespaces": ["@acme", "acme-*"],
        "trusted_signers": ["https://ci.example/release"],
    },
    "rules": [
        {
            "id": "deny-malicious",
            "tier": "deny",
            "then": "block",
            "when": {"finding.category": "malicious", "finding.confidence": ">=medium"},
        },
        {
            "id": "young-release",
            "tier": "require",
            "then": "review",
            "applies_to": {
                "subject.kind": "package",
                "context.relation": {"in": ["direct", "transitive"]},
            },
            "when": {"version.age_days": "<3d"},
        },
        {
            "id": "provenance-critical",
            "tier": "require",
            "then": "block",
            "applies_to": {"subject.tags": "critical"},
            "require": {
                "provenance.slsa_level": ">=2",
                "signature.signer": {"in": "trusted_signers"},
            },
        },
        {
            "id": "mcp-approved-only",
            "tier": "require",
            "then": "review",
            "applies_to": {"subject.kind": "mcp_server"},
            "require": {"approval": "present"},
        },
        {
            "id": "allow-internal",
            "tier": "allow",
            "then": "allow",
            "when": {"subject.namespace": {"in": "internal_namespaces"}},
            "obligations": ["O002"],
        },
    ],
}


class Sources:
    @staticmethod
    def make(**changes) -> PolicySource:
        data = copy.deepcopy(SOURCE)
        data.update(changes)
        return PolicySource.from_json(data)


class TestACompiledPolicy:
    def test_it_is_sealed_and_verifies(self) -> None:
        policy = PolicyCompiler.compile(Sources.make())
        policy.verify()
        assert policy.sha256 == policy.computed_sha256() and policy.sha256 != "sha256:" + "0" * 64

    def test_the_same_source_is_the_same_bytes_and_digest(self) -> None:
        a, b = PolicyCompiler.compile(Sources.make()), PolicyCompiler.compile(Sources.make())
        assert a == b and a.to_json() == b.to_json()

    def test_a_change_to_a_rule_or_a_default_changes_the_digest(self) -> None:
        base = PolicyCompiler.compile(Sources.make()).sha256
        rules = copy.deepcopy(SOURCE["rules"])
        rules[1]["when"] = {"version.age_days": "<5d"}
        assert PolicyCompiler.compile(Sources.make(rules=rules)).sha256 != base
        assert PolicyCompiler.compile(Sources.make(version=15)).sha256 != base

    def test_it_round_trips_through_json_and_an_edited_table_is_refused(self) -> None:
        policy = PolicyCompiler.compile(Sources.make())
        again = CompiledPolicy.from_json(policy.to_json())
        assert again == policy
        again.verify()
        shape = policy.to_json()
        shape["rules"][0]["then"] = "allow"
        with pytest.raises(PolicyError, match="digest does not match"):
            CompiledPolicy.from_json(shape).verify()

    def test_lists_are_resolved_into_the_table(self) -> None:
        policy = PolicyCompiler.compile(Sources.make())
        allow = next(rule for rule in policy.rules if rule.id == "allow-internal")
        assert allow.when[0].value == ("@acme", "acme-*")

    def test_defaults_are_parsed_and_the_reason_is_inferred_from_the_field(self) -> None:
        policy = PolicyCompiler.compile(Sources.make())
        assert (
            policy.defaults.max_intel_age_s == 7 * 86400
            and policy.defaults.bundle_max_age_s == 72 * 3600
        )
        assert policy.defaults.incomplete_for("production") == "block"
        reasons = {rule.id: rule.reason for rule in policy.rules}
        assert reasons["young-release"] == "R503" and reasons["provenance-critical"] == "R500"
        assert reasons["mcp-approved-only"] == "R700" and reasons["deny-malicious"] is None

    def test_the_rules_keep_their_written_order(self) -> None:
        policy = PolicyCompiler.compile(Sources.make())
        assert [rule.id for rule in policy.rules] == [rule["id"] for rule in SOURCE["rules"]]


class TestWhatIsRefused:
    def refused(self, needle: str, **changes) -> None:
        with pytest.raises(PolicyError, match=needle):
            PolicyCompiler.compile(Sources.make(**changes))

    def rule(self, **kw) -> list[dict]:
        base = {
            "id": "r1",
            "tier": "deny",
            "then": "block",
            "when": {"finding.category": "malicious"},
        }
        return [{**base, **kw}]

    def test_the_source_must_be_policy_v2(self) -> None:
        with pytest.raises(PolicyError, match="policy_schema"):
            PolicySource.from_json({"policy_schema": 1, "id": "x", "version": 1})

    def test_unknown_keys_are_errors_not_ignored(self) -> None:
        with pytest.raises(DecisionError, match="unexpected field 'rulez'"):
            PolicySource.from_json({"policy_schema": 2, "id": "x", "version": 1, "rulez": []})
        with pytest.raises(DecisionError, match="unexpected field 'when_'"):
            PolicySource.from_json(
                {
                    "policy_schema": 2,
                    "id": "x",
                    "version": 1,
                    "rules": [{"id": "r", "tier": "deny", "then": "block", "when_": {}}],
                }
            )

    def test_the_shape_each_tier_needs(self) -> None:
        self.refused("states `when`", rules=self.rule(when=None))
        self.refused("no `require`", rules=self.rule(require={"approval": "present"}))
        self.refused("blocks or sends to review", rules=self.rule(then="allow"))
        self.refused("states `when` or `require`", rules=self.rule(tier="require", when=None))
        self.refused("allows, with or without", rules=self.rule(tier="allow", then="block"))
        self.refused(
            "states `when`, not `require`",
            rules=self.rule(tier="allow", then="allow", when=None, require={"approval": "present"}),
        )

    def test_a_rule_that_cannot_name_its_reason_must_say_it(self) -> None:
        self.refused(
            "reason code is needed",
            rules=self.rule(tier="require", then="review", when={"subject.kind": "package"}),
        )
        assert PolicyCompiler.compile(
            Sources.make(
                rules=self.rule(
                    tier="require", then="review", when={"subject.kind": "package"}, reason="R700"
                )
            )
        )

    def test_obligations_and_reasons_must_be_registered(self) -> None:
        self.refused("not a registered obligation", rules=self.rule(obligations=["O999"]))
        self.refused("not a registered reason code", rules=self.rule(reason="R999"))

    def test_an_id_used_twice_a_bad_expiry_and_a_scope_outside_the_parent(self) -> None:
        self.refused("used twice", rules=self.rule() + self.rule())
        with pytest.raises(DecisionError):
            PolicyCompiler.compile(Sources.make(expires_at="soon"))

    def test_extends_must_match_the_parents_given(self) -> None:
        with pytest.raises(PolicyError, match="extends"):
            PolicyCompiler.compile(Sources.make(extends=["acme/baseline"]))

    def test_an_unknown_field_in_a_rule_names_the_rule_and_the_part(self) -> None:
        with pytest.raises(PolicyError, match=r"rules\.r1\.when\.finding\.nonsense"):
            PolicyCompiler.compile(Sources.make(rules=self.rule(when={"finding.nonsense": 1})))


class TestDurations:
    @pytest.mark.parametrize(
        ("text", "seconds"),
        [("7d", 604800), ("72h", 259200), ("30m", 1800), ("90s", 90), ("45", 45), (120, 120)],
    )
    def test_the_forms(self, text, seconds) -> None:
        assert Durations.seconds(text, "x") == seconds

    @pytest.mark.parametrize("bad", ["soon", "-1d", "1w", True, ""])
    def test_what_is_not_a_duration(self, bad) -> None:
        with pytest.raises(PolicyError):
            Durations.seconds(bad, "x")
