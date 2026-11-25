"""A policy bundle that loosens the policy is refused unless a current, signed loosening covers each loosening.

The client compares the offered bundle with the one it holds. A tightening needs nothing. A lowering, or a change it cannot prove is not one,
needs a loosening: a DSSE envelope the bundle carries (`loosenings`), signed by a policy key the pinned root delegated, naming what it relaxes
(`relaxes`), the version it relaxes from (`from_version`), `issued_at` and `expires_at` (at most 30 days apart, `issued_at` at most 5 minutes ahead of
the client's clock) and the id of the entry in the platform's decision log (`log_id`), which the client keeps for an auditor and does not check online.
A refusal is named `bundle_loosened` and leaves the held bundle as it was.
"""

from __future__ import annotations

import copy
from datetime import timedelta
from typing import Any

import pytest

from cordon_scanner.cloud.bundle_chain import BundleChain, BundleRefused
from cordon_scanner.cloud.bundle_loosening import Loosening
from cordon_scanner.decide.decision.compiler import PolicyCompiler
from cordon_scanner.decide.decision.policy_source import PolicySource
from cordon_scanner.intel.provenance._ed25519_signer import Ed25519Signer
from kits.bundle_kit import T0, Kit, Platform

LIFE = timedelta(days=90)
NOW = T0 + timedelta(hours=1)
DEFAULTS: dict[str, Any] = {
    "default": "review",
    "on_incomplete": {"*": "block", "ci": "review"},
    "unresolved": "block",
    "on_gaps": "block",
    "exceptions": "none",
    "max_intel_age": "7d",
    "bundle_max_age": "72h",
    "exception_max_age": "30d",
    "warn_until_measured": ["pypi"],
    "degrade": {"serve_last_allow_hours": 24},
}
DENY = {
    "id": "deny-malicious",
    "tier": "deny",
    "then": "block",
    "when": {"finding.category": "malicious"},
}
HIGH = {"id": "deny-high", "tier": "deny", "then": "review", "when": {"finding.severity": ">=high"}}
OK = {
    "id": "allow-internal",
    "tier": "allow",
    "then": "allow",
    "when": {"subject.tags": "internal"},
}


class Make:
    @staticmethod
    def policy(version: int = 1, *, rules: list[dict[str, Any]] | None = None, **defaults: Any):
        merged = copy.deepcopy(DEFAULTS)
        merged.update(defaults)
        return PolicyCompiler.compile(
            PolicySource.from_json(
                {
                    "policy_schema": 2,
                    "id": "acme/policy",
                    "version": version,
                    "scope": ["acme"],
                    "rules": copy.deepcopy([DENY, HIGH] if rules is None else rules),
                    "defaults": merged,
                    "expires_at": (T0 + LIFE).isoformat(),
                }
            )
        )

    @staticmethod
    def held(first=None, lists=None):
        """A runtime that holds version 1 of the chain, and the platform that signed it."""
        platform = Platform()
        platform.publish(first or Make.policy(1), issued=T0, expires=T0 + LIFE, lists=lists)
        runtime = Kit.runtime(platform)
        runtime.accept(platform.chain, NOW)
        return platform, runtime

    @staticmethod
    def grant(platform: Platform, relaxes: list[str], **kw: Any) -> dict[str, Any]:
        kw.setdefault("from_version", 1)
        kw.setdefault("issued", NOW - timedelta(minutes=1))
        kw.setdefault("expires", NOW + timedelta(days=2))
        return platform.loosening(relaxes=relaxes, **kw)

    @staticmethod
    def offer(platform, runtime, policy, *, loosenings=None, lists=None, at=NOW):
        envelope = platform.publish(
            policy, issued=T0, expires=T0 + LIFE, loosenings=loosenings, lists=lists
        )
        try:
            return runtime.accept([envelope], at)
        except BundleRefused:
            platform.chain.pop()  # a refused bundle is not part of the chain: the next offer is version 2 again
            platform.payloads.pop()
            raise


LOWERINGS: list[tuple[str, dict[str, Any], str]] = [
    ("default review to allow", {"default": "allow"}, "default:default"),
    (
        "incomplete in every environment to review",
        {"on_incomplete": {"*": "review", "ci": "review"}},
        "default:on_incomplete.*",
    ),
    (
        "incomplete in one environment to warn",
        {"on_incomplete": {"*": "block", "ci": "warn"}},
        "default:on_incomplete.ci",
    ),
    ("unresolved to review", {"unresolved": "review"}, "default:unresolved"),
    ("gaps to warn", {"on_gaps": "warn"}, "default:on_gaps"),
    ("exceptions from none to allow", {"exceptions": "allow"}, "default:exceptions"),
    ("a longer intel age", {"max_intel_age": "30d"}, "default:max_intel_age"),
    ("a longer bundle age", {"bundle_max_age": "200h"}, "default:bundle_max_age"),
    ("a longer exception age", {"exception_max_age": "90d"}, "default:exception_max_age"),
    (
        "another ecosystem warn-only",
        {"warn_until_measured": ["pypi", "npm"]},
        "default:warn_until_measured",
    ),
    (
        "a longer serve-last-allow window",
        {"degrade": {"serve_last_allow_hours": 48}},
        "default:serve_last_allow",
    ),
]


class TestATighteningNeedsNothing:
    @pytest.mark.parametrize(
        "change",
        [
            {"default": "block"},
            {"on_incomplete": {"*": "block", "ci": "block"}},
            {"unresolved": "block", "on_gaps": "block"},
            {"max_intel_age": "3d"},
            {"bundle_max_age": "24h"},
            {"exception_max_age": "7d"},
            {"warn_until_measured": []},
            {"degrade": {"serve_last_allow_hours": 12}},
            {},
        ],
    )
    def test_a_stricter_default_is_taken(self, change: dict[str, Any]) -> None:
        platform, runtime = Make.held()
        assert Make.offer(platform, runtime, Make.policy(2, **change)) == "new"

    def test_a_rule_added_a_rule_raised_and_an_allow_rule_removed_are_taken(self) -> None:
        platform, runtime = Make.held(Make.policy(1, rules=[DENY, {**HIGH, "then": "review"}, OK]))
        stricter = Make.policy(
            2,
            rules=[
                DENY,
                {**HIGH, "then": "block"},
                {
                    "id": "deny-new",
                    "tier": "deny",
                    "then": "block",
                    "when": {"finding.severity": "critical"},
                },
            ],
        )
        assert Make.offer(platform, runtime, stricter) == "new"

    def test_a_deny_list_that_grows_and_an_allow_list_that_shrinks_are_taken(self) -> None:
        platform, runtime = Make.held(lists={"deny": ["a"], "allow": ["x", "y"]})
        assert (
            Make.offer(
                platform, runtime, Make.policy(2), lists={"deny": ["a", "b"], "allow": ["x"]}
            )
            == "new"
        )


class TestALoweringNeedsALoosening:
    @pytest.mark.parametrize(("what", "change", "key"), LOWERINGS, ids=[x[0] for x in LOWERINGS])
    def test_each_lowering_of_a_default_is_refused_by_name_and_says_what(
        self, what: str, change: dict[str, Any], key: str
    ) -> None:
        platform, runtime = Make.held()
        with pytest.raises(BundleRefused) as caught:
            Make.offer(platform, runtime, Make.policy(2, **change))
        assert caught.value.name == "bundle_loosened" and key in str(caught.value), what
        assert runtime._held["version"] == 1  # the held bundle is as it was

    @pytest.mark.parametrize(("what", "change", "key"), LOWERINGS, ids=[x[0] for x in LOWERINGS])
    def test_and_taken_with_a_loosening_that_names_it(
        self, what: str, change: dict[str, Any], key: str
    ) -> None:
        platform, runtime = Make.held()
        grant = Make.grant(platform, [key])
        assert (
            Make.offer(platform, runtime, Make.policy(2, **change), loosenings=[grant]) == "new"
        ), what

    @pytest.mark.parametrize(
        ("rules", "key"),
        [
            ([HIGH], "rule:deny-malicious"),
            ([{**DENY, "then": "review"}, HIGH], "rule:deny-malicious"),
            ([{**DENY, "when": {"finding.category": "suspicious"}}, HIGH], "rule:deny-malicious"),
            ([DENY, HIGH, OK], "rule:allow-internal"),
            ([HIGH, DENY], "rules:order"),
        ],
        ids=[
            "a deny rule removed",
            "its outcome lowered",
            "its condition changed",
            "an allow rule added",
            "the order changed",
        ],
    )
    def test_a_rule_that_is_removed_lowered_changed_added_as_allow_or_moved_is_refused(
        self, rules: list[dict[str, Any]], key: str
    ) -> None:
        platform, runtime = Make.held()
        with pytest.raises(BundleRefused) as caught:
            Make.offer(platform, runtime, Make.policy(2, rules=rules))
        assert key in str(caught.value)
        assert (
            Make.offer(
                platform,
                runtime,
                Make.policy(2, rules=rules),
                loosenings=[Make.grant(platform, [key])],
            )
            == "new"
        )

    @pytest.mark.parametrize(
        ("held", "offered", "key"),
        [
            ({"deny": ["a", "b"]}, {"deny": ["a"]}, "list:bundle.deny"),
            ({"allow": ["x"]}, {"allow": ["x", "y"]}, "list:bundle.allow"),
            ({"notes": ["x"]}, {"notes": ["x", "y"]}, "list:bundle.notes"),
        ],
        ids=["a deny list shrinks", "an allow list grows", "a list of another name changes"],
    )
    def test_a_list_that_loosens_is_refused(
        self, held: dict[str, Any], offered: dict[str, Any], key: str
    ) -> None:
        platform, runtime = Make.held(lists=held)
        with pytest.raises(BundleRefused) as caught:
            Make.offer(platform, runtime, Make.policy(2), lists=offered)
        assert key in str(caught.value)

    def test_every_change_a_loosening_does_not_name_is_still_refused(self) -> None:
        platform, runtime = Make.held()
        two = Make.policy(2, default="allow", on_gaps="warn")
        with pytest.raises(BundleRefused) as caught:
            Make.offer(
                platform, runtime, two, loosenings=[Make.grant(platform, ["default:default"])]
            )
        assert "default:on_gaps" in str(caught.value) and "default:default" not in str(caught.value)
        assert (
            Make.offer(
                platform,
                runtime,
                two,
                loosenings=[
                    Make.grant(platform, ["default:default"]),
                    Make.grant(platform, ["default:on_gaps"], log_id="log:2"),
                ],
            )
            == "new"
        )


class TestWhatMakesALooseningCount:
    @staticmethod
    def refused(platform: Platform, runtime, *grants: dict[str, Any]) -> bool:
        try:
            Make.offer(platform, runtime, Make.policy(2, default="allow"), loosenings=list(grants))
        except BundleRefused as caught:
            return caught.name == "bundle_loosened"
        return False

    def test_a_good_one_counts_and_its_log_id_is_kept_for_the_auditor(self) -> None:
        platform, runtime = Make.held()
        assert not self.refused(
            platform, runtime, Make.grant(platform, ["default:default"], log_id="log:entry-42")
        )
        assert "log:entry-42" in runtime.loosening_log

    def test_an_expired_one_does_not_and_one_expiring_now_does(self) -> None:
        platform, runtime = Make.held()
        assert self.refused(
            platform,
            runtime,
            Make.grant(
                platform,
                ["default:default"],
                issued=NOW - timedelta(days=3),
                expires=NOW - timedelta(seconds=1),
            ),
        )
        assert not self.refused(
            platform,
            runtime,
            Make.grant(platform, ["default:default"], issued=NOW - timedelta(days=3), expires=NOW),
        )

    @pytest.mark.parametrize(
        ("ahead", "counts"),
        [
            (timedelta(minutes=4), True),
            (timedelta(minutes=5), True),
            (timedelta(minutes=5, seconds=1), False),
        ],
    )
    def test_one_issued_ahead_of_the_clients_clock_counts_only_within_five_minutes(
        self, ahead: timedelta, counts: bool
    ) -> None:
        platform, runtime = Make.held()
        grant = Make.grant(
            platform,
            ["default:default"],
            issued=NOW + ahead,
            expires=NOW + ahead + timedelta(days=1),
        )
        assert self.refused(platform, runtime, grant) is not counts

    @pytest.mark.parametrize(
        ("life", "counts"),
        [
            (timedelta(days=30), True),
            (timedelta(days=30, seconds=1), False),
            (timedelta(seconds=0), False),
            (-timedelta(days=1), False),
        ],
    )
    def test_one_may_last_at_most_thirty_days_and_must_end_after_it_began(
        self, life: timedelta, counts: bool
    ) -> None:
        platform, runtime = Make.held()
        issued = NOW - timedelta(minutes=1)
        assert (
            self.refused(
                platform,
                runtime,
                Make.grant(platform, ["default:default"], issued=issued, expires=issued + life),
            )
            is not counts
        )

    def test_one_that_relaxes_from_another_version_does_not(self) -> None:
        platform, runtime = Make.held()
        assert self.refused(
            platform, runtime, Make.grant(platform, ["default:default"], from_version=2)
        )
        assert self.refused(
            platform, runtime, Make.grant(platform, ["default:default"], from_version=0)
        )

    def test_one_signed_by_a_key_the_root_did_not_delegate_does_not(self) -> None:
        platform, runtime = Make.held()
        stranger = Ed25519Signer(Kit.seed("a stranger"))
        assert self.refused(
            platform, runtime, Make.grant(platform, ["default:default"], signer=stranger)
        )
        assert self.refused(
            platform, runtime, Make.grant(platform, ["default:default"], signer=platform.root)
        )  # the root key is not a policy key

    def test_one_for_another_tenant_or_scope_does_not(self) -> None:
        platform, runtime = Make.held()
        assert self.refused(
            platform, runtime, Make.grant(platform, ["default:default"], tenant="another-tenant")
        )
        assert self.refused(
            platform, runtime, Make.grant(platform, ["default:default"], scope="org:other")
        )

    def test_one_changed_after_it_was_signed_does_not(self) -> None:
        platform, runtime = Make.held()
        grant = Make.grant(platform, ["default:on_gaps"])
        document = BundleChain.unverified_payload_document(grant)
        document["relaxes"] = ["default:default"]
        import base64

        grant["payload"] = base64.b64encode(BundleChain.canonical(document)).decode("ascii")
        assert self.refused(platform, runtime, grant)

    @pytest.mark.parametrize(
        "broken",
        [
            "not an envelope",
            None,
            7,
            {},
            {"payloadType": "x", "payload": "!!", "signatures": []},
            {"payloadType": "application/vnd.cordon.loosening+json"},
        ],
    )
    def test_a_loosening_that_is_not_an_envelope_is_ignored_not_a_crash(
        self, broken: object
    ) -> None:
        platform, runtime = Make.held()
        assert self.refused(platform, runtime, broken)  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "field",
        ["relaxes", "log_id", "from_version", "issued_at", "expires_at", "tenant", "scope"],
    )
    def test_one_missing_a_field_does_not_count(self, field: str) -> None:
        platform, runtime = Make.held()
        grant = Make.grant(platform, ["default:default"])
        document = BundleChain.unverified_payload_document(grant)
        del document[field]
        assert self.refused(
            platform,
            runtime,
            platform.sign("application/vnd.cordon.loosening+json", document, platform.policy_key),
        )

    @pytest.mark.parametrize(
        "bad",
        [
            {"relaxes": []},
            {"relaxes": "default:default"},
            {"relaxes": [3]},
            {"log_id": ""},
            {"log_id": 7},
            {"from_version": "1"},
            {"from_version": True},
            {"issued_at": "not a time"},
            {"expires_at": "2026-11-20T09:00:00"},
        ],
    )
    def test_one_with_a_field_of_the_wrong_kind_does_not_count(self, bad: dict[str, Any]) -> None:
        platform, runtime = Make.held()
        grant = Make.grant(platform, ["default:default"])
        document = {**BundleChain.unverified_payload_document(grant), **bad}
        assert self.refused(
            platform,
            runtime,
            platform.sign("application/vnd.cordon.loosening+json", document, platform.policy_key),
        )

    def test_the_first_bundle_a_client_holds_needs_none(self) -> None:
        platform = Platform()
        envelope = platform.publish(Make.policy(1, default="allow"), issued=T0, expires=T0 + LIFE)
        assert Kit.runtime(platform).accept([envelope], NOW) == "new"


class TestAChainAndAFreshStart:
    def test_each_bundle_of_a_catch_up_chain_is_compared_with_the_one_before(self) -> None:
        platform, runtime = Make.held()
        two = platform.publish(Make.policy(2, default="block"), issued=T0, expires=T0 + LIFE)
        three = platform.publish(
            Make.policy(3, default="review"),
            issued=T0,
            expires=T0 + LIFE,
            loosenings=[Make.grant(platform, ["default:default"], from_version=2)],
        )
        assert runtime.accept([two, three], NOW) == "new"

    def test_a_loosening_for_the_wrong_step_of_the_chain_is_refused_and_nothing_is_taken(
        self,
    ) -> None:
        platform, runtime = Make.held()
        two = platform.publish(Make.policy(2, default="block"), issued=T0, expires=T0 + LIFE)
        three = platform.publish(
            Make.policy(3, default="review"),
            issued=T0,
            expires=T0 + LIFE,
            loosenings=[Make.grant(platform, ["default:default"], from_version=1)],
        )
        with pytest.raises(BundleRefused) as caught:
            runtime.accept([two, three], NOW)
        assert caught.value.name == "bundle_loosened"
        assert runtime._held["version"] == 1

    def test_a_fresh_start_is_compared_with_the_bundle_held_too(self) -> None:
        platform, runtime = Make.held()
        loose = platform.publish(Make.policy(2, default="allow"), issued=T0, expires=T0 + LIFE)
        with pytest.raises(BundleRefused) as caught:
            runtime.restart(loose, NOW)
        assert caught.value.name == "bundle_loosened"

    def test_a_fresh_start_with_a_loosening_is_taken(self) -> None:
        platform, runtime = Make.held()
        loose = platform.publish(
            Make.policy(2, default="allow"),
            issued=T0,
            expires=T0 + LIFE,
            loosenings=[Make.grant(platform, ["default:default"])],
        )
        assert runtime.restart(loose, NOW) == "new"


class TestTheComparisonItself:
    def test_nothing_differs_when_nothing_changed(self) -> None:
        platform, _ = Make.held()
        bundle = platform.payloads[0]
        assert Loosening.differences(bundle, bundle) == set()

    def test_a_bundle_without_a_policy_is_compared_by_its_lists_only(self) -> None:
        held = {"lists": {"deny": ["a", "b"]}}
        assert Loosening.differences(held, {"lists": {"deny": ["a"]}}) == {"list:bundle.deny"}
        assert Loosening.differences(held, {"lists": {"deny": ["a", "b", "c"]}}) == set()

    def test_the_scope_of_the_policy_and_its_mandatory_flag_are_held_too(self) -> None:
        platform, _ = Make.held()
        held = platform.payloads[0]
        wider = copy.deepcopy(held)
        wider["compiled_table"]["scope"] = ["acme", "other"]
        assert "scope" in Loosening.differences(held, wider)
        locked = copy.deepcopy(held)
        locked["compiled_table"]["mandatory"] = True
        unlocked = copy.deepcopy(held)
        unlocked["compiled_table"]["mandatory"] = False
        assert "mandatory" in Loosening.differences(locked, unlocked)
        assert "mandatory" not in Loosening.differences(unlocked, locked)
