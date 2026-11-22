"""Row BP-0-12: the execution plane keeps deciding with the control plane down, from the signed bundle it holds.

The kit plays the platform: a tenant root, a policy key it delegated, and bundles it signs (DSSE, Ed25519, chained by `prev_sha`).
The runtime takes them offline, decides through the single point entry, and refuses what does not verify or chain without losing
the bundle it holds. The chaos test kills the control plane in the middle of a load and asks that every question still gets its
decision, and the same decision as with the control plane up.
"""

from __future__ import annotations

import base64
import copy
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner.cloud.bundle_chain import BundleError, BundleRefused
from cordon_scanner.cloud.local_runtime import REQUIRED_BUNDLE, LocalRuntime
from cordon_scanner.cloud.local_store import LocalStore
from cordon_scanner.decide.decision.evidence import EvidenceSet
from cordon_scanner.decide.points import PointRuntime
from cordon_scanner.intel.provenance._ed25519_signer import Ed25519Signer
from kits.bundle_kit import BUNDLE, T0, Kit, Platform, Things, Upstream


class TestADecisionFromTheHeldBundle:
    def test_the_decision_is_the_held_policys_and_names_it(self) -> None:
        platform = Platform()
        runtime = Kit.runtime(platform)
        assert runtime.accept([Kit.first(platform, default="review")], T0) == "new"
        decision = Kit.ask(runtime, T0 + timedelta(minutes=5))
        assert decision.state == "REVIEW" and decision.reason_codes == ("R700",)
        assert decision.policy.id == "acme/policy" and decision.policy.version == 1

    def test_the_lists_beside_the_policy_are_kept_with_it(self) -> None:
        platform = Platform()
        runtime = Kit.runtime(platform)
        assert runtime.lists == {}
        runtime.accept([Kit.first(platform)], T0)
        assert runtime.lists == {"deny": ["pkg:npm/evil"]}

    def test_a_second_bundle_of_the_chain_replaces_the_first(self) -> None:
        platform = Platform()
        runtime = Kit.runtime(platform)
        runtime.accept([Kit.first(platform, default="review")], T0)
        second = platform.publish(
            Kit.compiled(2, T0 + timedelta(days=1), "block"),
            issued=T0,
            expires=T0 + timedelta(days=1),
        )
        assert runtime.accept([second], T0 + timedelta(minutes=1)) == "new"
        assert Kit.ask(runtime, T0 + timedelta(minutes=2)).state == "BLOCK"
        assert runtime.held is not None and runtime.held["version"] == 2

    def test_a_catch_up_of_two_bundles_is_taken_in_order(self) -> None:
        platform = Platform()
        runtime = Kit.runtime(platform)
        first = Kit.first(platform)
        second = platform.publish(
            Kit.compiled(2, T0 + timedelta(days=1), "review"),
            issued=T0,
            expires=T0 + timedelta(days=1),
        )
        assert runtime.accept([first, second], T0) == "new"
        assert runtime.held is not None and runtime.held["version"] == 2

    def test_the_same_bundle_again_is_nothing_new(self) -> None:
        platform = Platform()
        runtime = Kit.runtime(platform)
        first = Kit.first(platform)
        runtime.accept([first], T0)
        assert runtime.accept([first], T0) == "unchanged"


class TestNothingHeldYet:
    def test_the_baseline_is_asked_with_the_bundle_named_as_missing_and_a_production_gate_blocks(
        self,
    ) -> None:
        platform = Platform()
        runtime = Kit.runtime(platform)
        decision = Kit.ask(runtime, T0)
        assert decision.state == "BLOCK" and "R200" in decision.reason_codes
        assert REQUIRED_BUNDLE in decision.explanation.reasons[0].text


class TestWhenTheBundleIsTooOld:
    def test_the_policy_decides_per_environment_what_an_expired_bundle_means(self) -> None:
        platform = Platform()
        runtime = Kit.runtime(platform)
        runtime.accept([Kit.first(platform, lifetime=timedelta(hours=2))], T0)
        late = T0 + timedelta(hours=3)
        production = Kit.ask(runtime, late, "ci_gate", "production")
        ci = Kit.ask(runtime, late, "ci_gate", "ci")
        assert production.state == "BLOCK" and "R202" in production.reason_codes
        assert ci.state == "ALLOW" and "R202" in ci.reason_codes
        assert ci.relaxations is not None and ci.relaxations[0].environment == "ci"

    def test_before_the_expiry_nothing_is_said_about_it(self) -> None:
        platform = Platform()
        runtime = Kit.runtime(platform)
        runtime.accept([Kit.first(platform, lifetime=timedelta(hours=2))], T0)
        assert "R202" not in Kit.ask(runtime, T0 + timedelta(hours=1)).reason_codes


class TestWhatIsRefusedLeavesTheHeldBundleAlone:
    def held_and_unchanged(
        self, runtime: LocalRuntime, before: dict[str, Any], clock: datetime
    ) -> None:
        assert runtime.held == before
        assert Kit.ask(runtime, clock).state == "REVIEW"

    def test_a_forked_bundle(self) -> None:
        platform = Platform()
        runtime = Kit.runtime(platform)
        runtime.accept([Kit.first(platform, default="review")], T0)
        before = runtime.held
        payload = dict(platform.payloads[0])
        payload["issued_at"] = (
            T0 + timedelta(minutes=1)
        ).isoformat()  # version 1 signed again with another time
        forked = Platform.sign(BUNDLE, payload, platform.policy_key)
        with pytest.raises(BundleRefused) as caught:
            runtime.accept([forked], T0 + timedelta(minutes=2))
        assert caught.value.name == BundleRefused.FORKED
        self.held_and_unchanged(runtime, before or {}, T0 + timedelta(minutes=3))

    def test_a_bundle_signed_by_a_key_the_root_did_not_delegate(self) -> None:
        platform = Platform()
        runtime = Kit.runtime(platform)
        runtime.accept([Kit.first(platform, default="review")], T0)
        before = runtime.held
        stranger = Platform(policy_key=Ed25519Signer(Kit.seed("someone else")))
        bad = stranger.publish(
            Kit.compiled(1, T0 + timedelta(days=1)), issued=T0, expires=T0 + timedelta(days=1)
        )
        with pytest.raises(BundleError):
            runtime.accept([bad], T0)
        self.held_and_unchanged(runtime, before or {}, T0)

    def test_a_bundle_with_no_compiled_policy(self) -> None:
        platform = Platform()
        runtime = Kit.runtime(platform)
        bare = platform.publish(
            Kit.compiled(1, T0 + timedelta(days=1)),
            issued=T0,
            expires=T0 + timedelta(days=1),
            carry_policy=False,
        )
        with pytest.raises(BundleError, match="compiled_table"):
            runtime.accept([bare], T0)
        assert runtime.held is None

    def test_a_policy_that_outlives_its_bundle(self) -> None:
        platform = Platform()
        runtime = Kit.runtime(platform)
        long_policy = Kit.compiled(1, T0 + timedelta(days=30))
        bundle = platform.publish(long_policy, issued=T0, expires=T0 + timedelta(days=1))
        with pytest.raises(BundleError, match="outlives"):
            runtime.accept([bundle], T0)
        assert runtime.held is None

    def test_a_policy_altered_after_it_was_compiled(self) -> None:
        platform = Platform()
        runtime = Kit.runtime(platform)
        Kit.first(platform)
        payload = copy.deepcopy(platform.payloads[0])
        payload["compiled_table"]["version"] = 9  # the sha256 inside no longer matches
        envelope = Platform.sign(BUNDLE, payload, platform.policy_key)
        with pytest.raises(BundleError, match="not sound"):
            runtime.accept([envelope], T0)
        assert runtime.held is None


class TestTheControlPlaneDiesUnderLoad:
    """The chaos test of the row: a load of questions over every point, the control plane killed part of the way through."""

    @dataclass
    class ControlPlane:
        up: bool = True
        calls: int = 0

        def refresh(self) -> list[dict[str, Any]]:
            self.calls += 1
            if not self.up:
                raise ConnectionError("the control plane is down")
            return []

    QUESTIONS = 1400

    def load(self, kill_at: int | None) -> tuple[list[str], int, int]:
        platform = Platform()
        runtime = Kit.runtime(platform)
        runtime.accept([Kit.first(platform, default="review", lifetime=timedelta(days=2))], T0)
        plane = self.ControlPlane()
        outcomes: list[str] = []
        failures = 0
        for number in range(self.QUESTIONS):
            if kill_at is not None and number == kill_at:
                plane.up = False
            try:
                plane.refresh()
            except ConnectionError:
                failures += 1  # the refresh fails; the questions do not
            point = PointRuntime.POINTS[number % len(PointRuntime.POINTS)]
            decision = Kit.ask(runtime, T0 + timedelta(seconds=number), point, "production")
            outcomes.append(decision.canonical_bytes().hex())
        return outcomes, failures, plane.calls

    def test_every_question_is_answered_and_the_answers_are_the_ones_given_with_the_control_plane_up(
        self,
    ) -> None:
        steady, none_failed, _ = self.load(None)
        degraded, refresh_failures, calls = self.load(self.QUESTIONS // 3)
        assert none_failed == 0 and refresh_failures == self.QUESTIONS - self.QUESTIONS // 3
        assert calls == self.QUESTIONS
        assert len(degraded) == self.QUESTIONS == len(steady)
        assert degraded == steady


class TestAnOfflineRunWithTheStore:
    """BP-2-6: with no network the runtime decides from the store and queues its uploads, then drains them on reconnect."""

    def test_decisions_made_offline_are_queued_and_sent_oldest_first_on_reconnect(
        self, tmp_path: Path
    ) -> None:
        platform = Platform()
        store = LocalStore(tmp_path)
        runtime = Kit.runtime(platform, store)
        runtime.accept([Kit.first(platform, default="review")], T0)
        decisions = [
            runtime.ask(
                "firewall",
                artifact,
                EvidenceSet(),
                T0 + timedelta(seconds=n),
                environment="production",
                scope_path=("acme",),
            )
            for n, artifact in enumerate(Things.artifacts(6))
        ]
        assert [json.loads(item.body)["decision"] for item in store.pending()] == [
            d.to_json() for d in decisions
        ]
        upstream = Upstream()
        drained = runtime.drain(upstream)
        assert (drained.sent, drained.left) == (6, 0)
        assert [json.loads(upstream.received[i])["decision"] for i in upstream.order] == [
            d.to_json() for d in decisions
        ]

    def test_a_connection_that_drops_mid_drain_loses_nothing_and_sends_nothing_twice(
        self, tmp_path: Path
    ) -> None:
        platform = Platform()
        runtime = Kit.runtime(platform, LocalStore(tmp_path))
        runtime.accept([Kit.first(platform)], T0)
        for number, artifact in enumerate(Things.artifacts(5)):
            runtime.ask(
                "cli",
                artifact,
                EvidenceSet(),
                T0 + timedelta(seconds=number),
                environment="production",
            )
        upstream = Upstream(fail_on=3)
        assert runtime.drain(upstream).left == 3
        assert runtime.drain(upstream).left == 0
        assert len(upstream.received) == 5 and len(upstream.order) == 5

    def test_the_same_question_in_the_same_moment_is_answered_from_the_store_and_queued_once(
        self, tmp_path: Path
    ) -> None:
        platform = Platform()
        store = LocalStore(tmp_path)
        runtime = Kit.runtime(platform, store)
        runtime.accept([Kit.first(platform)], T0)
        asked = [
            runtime.ask(
                "cli",
                Things.artifacts(1)[0],
                EvidenceSet(),
                T0 + timedelta(seconds=5),
                environment="production",
            )
            for _ in range(3)
        ]
        assert (
            asked[0].canonical_bytes() == asked[1].canonical_bytes() == asked[2].canonical_bytes()
        )
        assert len(store.pending()) == 1 and store.cache_size() == 1

    def test_a_kept_decision_is_the_decision_that_would_be_made(self, tmp_path: Path) -> None:
        platform = Platform()
        kept = Kit.runtime(platform, LocalStore(tmp_path))
        plain = Kit.runtime(platform)
        for runtime in (kept, plain):
            runtime.accept([Kit.first(platform, default="review")], T0)
        for number, artifact in enumerate(Things.artifacts(20)):
            clock = T0 + timedelta(seconds=number)
            first = kept.ask("cli", artifact, EvidenceSet(), clock, environment="production")
            again = kept.ask("cli", artifact, EvidenceSet(), clock, environment="production")
            assert (
                first.canonical_bytes()
                == again.canonical_bytes()
                == plain.ask(
                    "cli", artifact, EvidenceSet(), clock, environment="production"
                ).canonical_bytes()
            )

    def test_after_a_restart_the_bundle_kept_decides_and_an_expired_one_is_the_policys_r202(
        self, tmp_path: Path
    ) -> None:
        platform = Platform()
        Kit.runtime(platform, LocalStore(tmp_path)).accept(
            [Kit.first(platform, lifetime=timedelta(hours=2))], T0
        )
        restarted = Kit.runtime(platform, LocalStore(tmp_path))
        assert restarted.held is None
        assert restarted.resume(T0 + timedelta(days=2)) is True
        late = T0 + timedelta(days=2)
        production = Kit.ask(restarted, late, "ci_gate", "production")
        ci = Kit.ask(restarted, late, "ci_gate", "ci")
        assert production.state == "BLOCK" and "R202" in production.reason_codes
        assert ci.state == "ALLOW" and "R202" in ci.reason_codes

    def test_a_bundle_kept_on_disk_that_was_changed_is_not_taken(self, tmp_path: Path) -> None:
        platform = Platform()
        store = LocalStore(tmp_path)
        Kit.runtime(platform, store).accept([Kit.first(platform, default="review")], T0)
        envelope = store.load_bundle()[0]  # type: ignore[index]
        body = json.loads(base64.b64decode(envelope["payload"]))
        body["expires_at"] = (T0 + timedelta(days=3650)).isoformat()
        envelope["payload"] = base64.b64encode(json.dumps(body).encode()).decode("ascii")
        store.save_bundle([envelope])
        restarted = Kit.runtime(platform, LocalStore(tmp_path))
        assert restarted.resume(T0 + timedelta(minutes=1)) is False and restarted.held is None
        assert "R200" in Kit.ask(restarted, T0 + timedelta(minutes=1)).reason_codes

    def test_a_restart_with_nothing_kept_or_no_store_holds_nothing(self, tmp_path: Path) -> None:
        platform = Platform()
        assert Kit.runtime(platform, LocalStore(tmp_path)).resume(T0) is False
        assert Kit.runtime(platform).resume(T0) is False

    def test_the_age_of_the_stored_intel_snapshot_is_the_age_the_policy_checks(
        self, tmp_path: Path
    ) -> None:
        platform = Platform()
        store = LocalStore(tmp_path)
        runtime = Kit.runtime(platform, store)
        policy = Kit.compiled(1, T0 + timedelta(days=1), max_intel_age=3600)
        runtime.accept([platform.publish(policy, issued=T0, expires=T0 + timedelta(days=1))], T0)
        store.put_blob("intel", "snapshot", b"snapshot", T0.isoformat())
        stale = Kit.ask(runtime, T0 + timedelta(hours=3), "ci_gate", "production")
        fresh = Kit.ask(runtime, T0 + timedelta(minutes=30), "ci_gate", "production")
        assert "R201" not in fresh.reason_codes
        assert "R201" in stale.reason_codes and stale.state == "BLOCK"

    def test_a_full_outbox_does_not_change_a_decision(self, tmp_path: Path) -> None:
        platform = Platform()
        small = Kit.runtime(platform, LocalStore(tmp_path / "small", max_pending=2))
        roomy = Kit.runtime(platform, LocalStore(tmp_path / "roomy"))
        for runtime in (small, roomy):
            runtime.accept([Kit.first(platform, default="review")], T0)
        for number, artifact in enumerate(Things.artifacts(5)):
            clock = T0 + timedelta(seconds=number)
            assert (
                small.ask(
                    "cli", artifact, EvidenceSet(), clock, environment="production"
                ).canonical_bytes()
                == roomy.ask(
                    "cli", artifact, EvidenceSet(), clock, environment="production"
                ).canonical_bytes()
            )
        assert small.drain(Upstream()).left == 0
