"""Row BP-0-12: the execution plane keeps deciding with the control plane down, from the signed bundle it holds.

The kit plays the platform: a tenant root, a policy key it delegated, and bundles it signs (DSSE, Ed25519, chained by `prev_sha`).
The runtime takes them offline, decides through the single point entry, and refuses what does not verify or chain without losing
the bundle it holds. The chaos test kills the control plane in the middle of a load and asks that every question still gets its
decision, and the same decision as with the control plane up.
"""

from __future__ import annotations

import base64
import copy
import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from cordon_scanner.cloud.bundle_chain import BundleChain, BundleError, BundleRefused, Dsse
from cordon_scanner.cloud.local_runtime import REQUIRED_BUNDLE, LocalRuntime
from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.decide.decision.compiler import PolicyCompiler
from cordon_scanner.decide.decision.evidence import ArtifactRef, EvidenceSet
from cordon_scanner.decide.decision.policy_source import PolicySource
from cordon_scanner.decide.decision.table import CompiledPolicy
from cordon_scanner.decide.points import PointRuntime
from cordon_scanner.intel.provenance._ed25519_signer import Ed25519Signer

BUNDLE = "application/vnd.cordon.policy-bundle+json"
TENANT = "tenant-under-test"
SCOPE = "org:acme"
T0 = datetime(2026, 11, 19, 8, 0, tzinfo=UTC)
ARTIFACT = ArtifactRef(
    kind="package",
    subject_id="pkg:npm/left-pad",
    digest=ArtifactDigests.of_bytes(b"left-pad"),
    ecosystem="npm",
    released_at="2026-06-01T00:00:00Z",
)


@dataclass
class Platform:
    """The tenant's control plane, as far as a client sees it: keys, a delegation, and the chain of bundles."""

    root: Ed25519Signer = field(default_factory=lambda: Ed25519Signer(Kit.seed("root")))
    policy_key: Ed25519Signer = field(default_factory=lambda: Ed25519Signer(Kit.seed("policy")))
    chain: list[dict[str, Any]] = field(default_factory=list)  # signed envelopes, oldest first
    payloads: list[dict[str, Any]] = field(default_factory=list)

    @staticmethod
    def sign(payload_type: str, document: dict[str, Any], signer: Ed25519Signer) -> dict[str, Any]:
        body = BundleChain.canonical(document)
        signature = signer.sign(Dsse.pae(payload_type, body))
        return {
            "payloadType": payload_type,
            "payload": base64.b64encode(body).decode("ascii"),
            "signatures": [
                {
                    "keyid": Dsse.keyid(signer.public),
                    "sig": base64.b64encode(signature).decode("ascii"),
                }
            ],
        }

    def delegation(self) -> dict[str, Any]:
        document = {
            "_type": "cordon.delegation/v1",
            "tenant": TENANT,
            "issued_at": T0.isoformat(),
            "keys": [
                {
                    "keyid": Dsse.keyid(self.policy_key.public),
                    "public": self.policy_key.public.hex(),
                    "role": "policy",
                    "not_before": (T0 - timedelta(days=1)).isoformat(),
                    "version": 1,
                }
            ],
        }
        return self.sign("application/vnd.cordon.delegation+json", document, self.root)

    def publish(
        self,
        policy: CompiledPolicy,
        *,
        issued: datetime,
        expires: datetime,
        carry_policy: bool = True,
        previous_sha: str | None = None,
    ) -> dict[str, Any]:
        version = len(self.chain) + 1
        prev = previous_sha
        if prev is None:
            prev = BundleChain.payload_sha(self.payloads[-1]) if self.payloads else ""
        document: dict[str, Any] = {
            "tenant": TENANT,
            "scope": SCOPE,
            "version": version,
            "prev_sha": prev,
            "issued_at": issued.isoformat(),
            "expires_at": expires.isoformat(),
            "signer_keyid": Dsse.keyid(self.policy_key.public),
            "lists": {},
        }
        if carry_policy:
            document["policy"] = policy.to_json()
        envelope = self.sign("application/vnd.cordon.policy-bundle+json", document, self.policy_key)
        self.chain.append(envelope)
        self.payloads.append(document)
        return envelope


class Kit:
    @staticmethod
    def seed(label: str) -> bytes:
        return hashlib.sha256(label.encode()).digest()

    @staticmethod
    def compiled(version: int, expires: datetime, default: str = "allow") -> CompiledPolicy:
        return PolicyCompiler.compile(
            PolicySource.from_json(
                {
                    "policy_schema": 2,
                    "id": "acme/policy",
                    "version": version,
                    "scope": ["acme"],
                    "rules": [],
                    "defaults": {"default": default, "on_incomplete": {"*": "block", "ci": "warn"}},
                    "expires_at": expires.isoformat(),
                }
            )
        )

    @staticmethod
    def runtime(platform: Platform) -> LocalRuntime:
        return LocalRuntime(
            root_public=platform.root.public,
            delegation=platform.delegation(),
            tenant=TENANT,
            baseline=Kit.compiled(1, T0 + timedelta(days=3650), default="allow"),
        )

    @staticmethod
    def first(
        platform: Platform, *, default: str = "allow", lifetime: timedelta = timedelta(days=1)
    ) -> dict[str, Any]:
        expires = T0 + lifetime
        return platform.publish(Kit.compiled(1, expires, default), issued=T0, expires=expires)

    @staticmethod
    def ask(
        runtime: LocalRuntime, clock: datetime, point: str = "cli", environment: str = "production"
    ):
        return runtime.ask(
            point, ARTIFACT, EvidenceSet(), clock, environment=environment, scope_path=("acme",)
        )


class TestADecisionFromTheHeldBundle:
    def test_the_decision_is_the_held_policys_and_names_it(self) -> None:
        platform = Platform()
        runtime = Kit.runtime(platform)
        assert runtime.accept([Kit.first(platform, default="review")], T0) == "new"
        decision = Kit.ask(runtime, T0 + timedelta(minutes=5))
        assert decision.state == "REVIEW" and decision.reason_codes == ("R700",)
        assert decision.policy.id == "acme/policy" and decision.policy.version == 1

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
        with pytest.raises(BundleError, match="no compiled policy"):
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
        payload["policy"]["version"] = 9  # the sha256 inside no longer matches
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
