"""Rows BP-8-13 to BP-8-17 and BP-15-16: what a point does when the control plane, the bundle, the intelligence or the registry is not
there, at the three kinds of point (a production gate, a CI gate, a developer's machine), and what it refuses to trust.

* Degrade 1 (BP-8-13): the bundle is valid and the control plane is down: every point decides locally, all of them.
* Degrade 2 (BP-8-14): the bundle has expired: production blocks (R202), CI and developers warn.
* Degrade 3 (BP-8-15): the intelligence is older than the policy allows: production blocks a new digest (R201) and allows one it
  allowed before; CI and developers warn.
* Degrade 4 (BP-8-16): an analysis left parts of the content unread: block at all three, and the explanation names the part (R204).
* Degrade 5 (BP-8-17): the registry cannot be reached: a digest allowed before is served from what was kept; an unknown one is refused.
* Pins (BP-15-16): a bundle signed by any key the pinned roots did not delegate is refused at every point.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from cordon_scanner.cloud.bundle_chain import BundleError
from cordon_scanner.cloud.local_runtime import LocalRuntime
from cordon_scanner.cloud.local_store import LocalStore
from cordon_scanner.decide.decision.evidence import EvidenceSet, GapFact
from cordon_scanner.decide.points import PointRuntime
from cordon_scanner.intel.provenance._ed25519_signer import Ed25519Signer
from kits.bundle_kit import T0, Kit, Platform, Things

#: The three kinds of point: (point, environment). Production blocks what the policy says to block there; CI and developers warn.
PRODUCTION = ("deploy_admission", "production")
CI = ("ci_gate", "ci")
DEVELOPER = ("cli", "dev")
KINDS = (PRODUCTION, CI, DEVELOPER)
LEVELS = {"*": "block", "ci": "warn", "dev": "warn"}


class World:
    @staticmethod
    def runtime(
        tmp_path: Path,
        *,
        max_intel_age: int | None = None,
        lifetime: timedelta = timedelta(days=2),
        serve_last_allow_hours: int | None = None,
    ) -> LocalRuntime:
        platform = Platform()
        runtime = Kit.runtime(platform, LocalStore(tmp_path))
        expires = T0 + lifetime
        policy = Kit.compiled(
            1,
            expires,
            max_intel_age=max_intel_age,
            on_incomplete=LEVELS,
            serve_last_allow_hours=serve_last_allow_hours,
        )
        runtime.accept([platform.publish(policy, issued=T0, expires=expires)], T0)
        return runtime

    @staticmethod
    def ask(
        runtime: LocalRuntime,
        kind: tuple[str, str],
        artifact,
        clock,
        evidence: EvidenceSet | None = None,
    ):
        point, environment = kind
        return runtime.answer(
            point,
            artifact,
            evidence or EvidenceSet(),
            clock,
            environment=environment,
            scope_path=("acme",),
        )


class TestDegradeOneTheControlPlaneIsDown:
    def test_every_point_decides_locally_and_all_of_them_answer(self, tmp_path: Path) -> None:
        runtime = World.runtime(tmp_path)
        asked = answered = 0
        for number, artifact in enumerate(Things.artifacts(210)):
            point = PointRuntime.POINTS[number % len(PointRuntime.POINTS)]
            environment = ("production", "ci", "dev")[number % 3]
            asked += 1
            decision = runtime.ask(
                point,
                artifact,
                EvidenceSet(),
                T0 + timedelta(seconds=number),
                environment=environment,
                scope_path=("acme",),
            )
            answered += decision.state in ("ALLOW", "REVIEW", "BLOCK")
        assert asked == answered == 210


class TestDegradeTwoTheBundleHasExpired:
    def test_production_blocks_and_ci_and_developers_warn(self, tmp_path: Path) -> None:
        runtime = World.runtime(tmp_path, lifetime=timedelta(hours=2))
        late = T0 + timedelta(hours=3)
        found = {
            kind[1]: World.ask(runtime, kind, Things.artifacts(1)[0], late).decision
            for kind in KINDS
        }
        assert {env: d.state for env, d in found.items()} == {
            "production": "BLOCK",
            "ci": "ALLOW",
            "dev": "ALLOW",
        }
        assert all("R202" in d.reason_codes for d in found.values())
        assert found["production"].relaxations is None
        assert [item.environment for item in found["ci"].relaxations or ()] == ["ci"]


class TestDegradeThreeTheIntelligenceIsStale:
    @staticmethod
    def stored(tmp_path: Path) -> tuple[LocalRuntime, LocalStore]:
        runtime = World.runtime(tmp_path, max_intel_age=3600)
        store = LocalStore(tmp_path)
        store.put_blob("intel", "snapshot", b"snapshot", T0.isoformat())
        return runtime, store

    def test_production_allows_what_it_allowed_and_blocks_a_new_digest_and_ci_and_developers_warn(
        self, tmp_path: Path
    ) -> None:
        runtime, _ = self.stored(tmp_path)
        known, new = Things.artifacts(2)
        fresh = T0 + timedelta(minutes=10)
        for kind in KINDS:
            assert World.ask(runtime, kind, known, fresh).decision.state == "ALLOW"
        stale = T0 + timedelta(hours=3)
        production = World.ask(runtime, PRODUCTION, known, stale)
        assert (production.decision.state, production.source) == ("ALLOW", "remembered")
        blocked = World.ask(runtime, PRODUCTION, new, stale)
        assert blocked.decision.state == "BLOCK" and "R201" in blocked.decision.reason_codes
        assert blocked.source == "decided"
        for kind in (CI, DEVELOPER):
            warned = World.ask(runtime, kind, new, stale).decision
            assert warned.state == "ALLOW" and "R201" in warned.reason_codes

    def test_what_was_allowed_in_ci_does_not_allow_production(self, tmp_path: Path) -> None:
        runtime, _ = self.stored(tmp_path)
        artifact = Things.artifacts(1)[0]
        World.ask(runtime, CI, artifact, T0 + timedelta(minutes=10))
        stale = World.ask(runtime, PRODUCTION, artifact, T0 + timedelta(hours=3))
        assert stale.decision.state == "BLOCK"

    def test_an_allow_older_than_the_window_is_not_served(self, tmp_path: Path) -> None:
        platform = Platform()
        store = LocalStore(tmp_path)
        runtime = Kit.runtime(platform, store)
        expires = T0 + timedelta(days=2)
        policy = Kit.compiled(
            1, expires, max_intel_age=3600, on_incomplete=LEVELS, serve_last_allow_hours=1
        )
        runtime.accept([platform.publish(policy, issued=T0, expires=expires)], T0)
        store.put_blob("intel", "snapshot", b"snapshot", T0.isoformat())
        artifact = Things.artifacts(1)[0]
        World.ask(runtime, PRODUCTION, artifact, T0 + timedelta(minutes=10))
        assert (
            World.ask(runtime, PRODUCTION, artifact, T0 + timedelta(minutes=50)).decision.state
            == "ALLOW"
        )
        assert (
            World.ask(runtime, PRODUCTION, artifact, T0 + timedelta(hours=3)).decision.state
            == "BLOCK"
        )

    def test_an_allow_under_another_policy_is_not_served(self, tmp_path: Path) -> None:
        platform = Platform()
        store = LocalStore(tmp_path)
        runtime = Kit.runtime(platform, store)
        first = Kit.compiled(1, T0 + timedelta(days=2), max_intel_age=3600, on_incomplete=LEVELS)
        runtime.accept([platform.publish(first, issued=T0, expires=T0 + timedelta(days=2))], T0)
        store.put_blob("intel", "snapshot", b"snapshot", T0.isoformat())
        artifact = Things.artifacts(1)[0]
        World.ask(runtime, PRODUCTION, artifact, T0 + timedelta(minutes=10))
        second = Kit.compiled(2, T0 + timedelta(days=2), max_intel_age=3600, on_incomplete=LEVELS)
        runtime.accept(
            [platform.publish(second, issued=T0, expires=T0 + timedelta(days=2))],
            T0 + timedelta(minutes=20),
        )
        assert (
            World.ask(runtime, PRODUCTION, artifact, T0 + timedelta(hours=3)).decision.state
            == "BLOCK"
        )

    def test_a_digest_with_a_finding_is_never_served_from_an_earlier_allow(
        self, tmp_path: Path
    ) -> None:
        from cordon_scanner.decide.decision.evidence import FindingFact

        platform = Platform()
        rule = {
            "id": "deny-suspicious",
            "tier": "deny",
            "then": "block",
            "when": {"finding.category": "suspicious"},
        }
        expires = T0 + timedelta(days=2)
        policy = Kit.compiled(3, expires, max_intel_age=3600, on_incomplete=LEVELS, rules=[rule])
        runtime = Kit.runtime(platform, LocalStore(tmp_path / "again"))
        runtime.accept([platform.publish(policy, issued=T0, expires=expires)], T0)
        LocalStore(tmp_path / "again").put_blob("intel", "snapshot", b"s", T0.isoformat())
        artifact = Things.artifacts(1)[0]
        World.ask(runtime, PRODUCTION, artifact, T0 + timedelta(minutes=10))
        finding = FindingFact(
            rule_id="SUSPECT.X.001", severity="high", confidence="high", category="suspicious"
        )
        found = World.ask(
            runtime, PRODUCTION, artifact, T0 + timedelta(hours=3), EvidenceSet(findings=(finding,))
        )
        assert found.decision.state == "BLOCK" and found.source == "decided"


class TestDegradeFourTheAnalysisIsIncomplete:
    def test_it_blocks_at_all_three_and_the_explanation_names_the_part(
        self, tmp_path: Path
    ) -> None:
        runtime = World.runtime(tmp_path)
        gap = GapFact(rule_id="SUSPECT.PACKAGE.UNPARSEABLE.001", path="lib/index.js")
        for kind in KINDS:
            decision = World.ask(
                runtime,
                kind,
                Things.artifacts(1)[0],
                T0 + timedelta(minutes=5),
                EvidenceSet(gaps=(gap,)),
            ).decision
            assert decision.state == "BLOCK" and "R204" in decision.reason_codes, kind
            text = " ".join(reason.text for reason in decision.explanation.reasons)
            assert "SUSPECT.PACKAGE.UNPARSEABLE.001" in text and "lib/index.js" in text

    def test_an_earlier_allow_does_not_cover_an_unread_part(self, tmp_path: Path) -> None:
        runtime = World.runtime(tmp_path)
        artifact = Things.artifacts(1)[0]
        World.ask(runtime, PRODUCTION, artifact, T0 + timedelta(minutes=1))
        gap = GapFact(rule_id="SUSPECT.PACKAGE.UNPARSEABLE.001", path="lib/index.js")
        later = World.ask(
            runtime, PRODUCTION, artifact, T0 + timedelta(minutes=2), EvidenceSet(gaps=(gap,))
        )
        assert later.decision.state == "BLOCK" and later.source == "decided"


class TestDegradeFiveTheRegistryIsUnreachable:
    UNREACHABLE = EvidenceSet(required_missing=("registry",))

    def test_a_digest_allowed_before_is_served_and_an_unknown_one_is_refused(
        self, tmp_path: Path
    ) -> None:
        runtime = World.runtime(tmp_path)
        known, unknown = Things.artifacts(2)
        World.ask(runtime, PRODUCTION, known, T0 + timedelta(minutes=1))
        later = T0 + timedelta(minutes=30)
        served = World.ask(runtime, PRODUCTION, known, later, self.UNREACHABLE)
        refused = World.ask(runtime, PRODUCTION, unknown, later, self.UNREACHABLE)
        assert (served.decision.state, served.source) == ("ALLOW", "remembered")
        assert refused.decision.state == "BLOCK" and "R200" in refused.decision.reason_codes

    def test_it_is_the_same_at_the_firewall_point(self, tmp_path: Path) -> None:
        runtime = World.runtime(tmp_path)
        known, unknown = Things.artifacts(2)
        firewall = ("firewall", "production")
        World.ask(runtime, firewall, known, T0 + timedelta(minutes=1))
        later = T0 + timedelta(minutes=30)
        assert (
            World.ask(runtime, firewall, known, later, self.UNREACHABLE).decision.state == "ALLOW"
        )
        assert (
            World.ask(runtime, firewall, unknown, later, self.UNREACHABLE).decision.state == "BLOCK"
        )

    def test_after_the_bundle_expires_nothing_is_served(self, tmp_path: Path) -> None:
        runtime = World.runtime(tmp_path, lifetime=timedelta(hours=2))
        known = Things.artifacts(1)[0]
        World.ask(runtime, PRODUCTION, known, T0 + timedelta(minutes=1))
        expired = World.ask(runtime, PRODUCTION, known, T0 + timedelta(hours=3), self.UNREACHABLE)
        assert expired.decision.state == "BLOCK" and expired.source == "decided"
        assert "R202" in expired.decision.reason_codes

    def test_nothing_is_remembered_without_a_store(self) -> None:
        platform = Platform()
        runtime = Kit.runtime(platform)
        expires = T0 + timedelta(days=2)
        policy = Kit.compiled(1, expires, on_incomplete=LEVELS)
        runtime.accept([platform.publish(policy, issued=T0, expires=expires)], T0)
        known = Things.artifacts(1)[0]
        World.ask(runtime, PRODUCTION, known, T0 + timedelta(minutes=1))
        assert (
            World.ask(
                runtime, PRODUCTION, known, T0 + timedelta(minutes=30), self.UNREACHABLE
            ).decision.state
            == "BLOCK"
        )


class TestThePinnedRootsAreTheOnlyOnesTrusted:
    """BP-15-16: a bundle signed by anything else is refused by the CLI, the hook and the firewall."""

    POINTS = ("cli", "agent_hook", "firewall")

    @staticmethod
    def _refuses(runtime: LocalRuntime, envelope: dict[str, Any], point: str) -> None:
        with pytest.raises(BundleError):
            runtime.accept([envelope], T0)
        assert runtime.held is None
        decision = runtime.ask(
            point,
            Things.artifacts(1)[0],
            EvidenceSet(),
            T0,
            environment="production",
            scope_path=("acme",),
        )
        assert decision.state == "BLOCK" and "R200" in decision.reason_codes

    @pytest.mark.parametrize("point", POINTS)
    def test_a_bundle_signed_by_a_key_nobody_delegated(self, point: str) -> None:
        platform = Platform()
        stranger = Platform(policy_key=Ed25519Signer(Kit.seed("a stranger's policy key")))
        stranger.root = platform.root  # the same root, but the policy key was never delegated by it
        expires = T0 + timedelta(days=1)
        envelope = stranger.publish(Kit.compiled(1, expires), issued=T0, expires=expires)
        self._refuses(Kit.runtime(platform), envelope, point)

    @pytest.mark.parametrize("point", POINTS)
    def test_a_bundle_of_another_root_s_platform(self, point: str) -> None:
        platform = Platform()
        other = Platform(
            root=Ed25519Signer(Kit.seed("another root")),
            policy_key=Ed25519Signer(Kit.seed("another policy key")),
        )
        expires = T0 + timedelta(days=1)
        envelope = other.publish(Kit.compiled(1, expires), issued=T0, expires=expires)
        self._refuses(Kit.runtime(platform), envelope, point)

    @pytest.mark.parametrize("point", POINTS)
    def test_a_delegation_that_another_root_signed(self, point: str) -> None:
        platform = Platform()
        other = Platform(root=Ed25519Signer(Kit.seed("another root")))
        runtime = Kit.runtime(platform, delegation=other.delegation())
        self._refuses(runtime, Kit.first(platform), point)

    @pytest.mark.parametrize("point", POINTS)
    def test_a_good_bundle_is_still_taken_afterwards(self, point: str) -> None:
        platform = Platform()
        runtime = Kit.runtime(platform)
        other = Platform(
            root=Ed25519Signer(Kit.seed("another root")),
            policy_key=Ed25519Signer(Kit.seed("another policy key")),
        )
        expires = T0 + timedelta(days=1)
        with pytest.raises(BundleError):
            runtime.accept(
                [other.publish(Kit.compiled(1, expires), issued=T0, expires=expires)], T0
            )
        assert runtime.accept([Kit.first(platform)], T0) == "new"
        assert Kit.ask(runtime, T0 + timedelta(minutes=1), point).state == "ALLOW"


class TestTheWindowIsThePolicys:
    """`defaults.degrade.serve_last_allow_hours` (default 24, at most 168, 0 off) and the relaxation a served ALLOW records."""

    @staticmethod
    def served(tmp_path: Path, hours: int | None, later: timedelta):
        runtime = World.runtime(
            tmp_path, max_intel_age=3600, serve_last_allow_hours=hours, lifetime=timedelta(days=10)
        )
        LocalStore(tmp_path).put_blob("intel", "snapshot", b"s", T0.isoformat())
        artifact = Things.artifacts(1)[0]
        World.ask(runtime, PRODUCTION, artifact, T0 + timedelta(minutes=10))
        return World.ask(runtime, PRODUCTION, artifact, T0 + later)

    def test_with_nothing_stated_it_is_24_hours(self, tmp_path: Path) -> None:
        assert self.served(tmp_path / "a", None, timedelta(hours=23)).source == "remembered"
        assert self.served(tmp_path / "b", None, timedelta(hours=25)).source == "decided"

    def test_a_longer_window_serves_longer_and_168_hours_is_the_most(self, tmp_path: Path) -> None:
        assert self.served(tmp_path / "a", 168, timedelta(hours=100)).source == "remembered"
        assert self.served(tmp_path / "b", 48, timedelta(hours=30)).source == "remembered"
        assert self.served(tmp_path / "c", 48, timedelta(hours=60)).source == "decided"

    def test_zero_turns_it_off(self, tmp_path: Path) -> None:
        assert self.served(tmp_path, 0, timedelta(hours=3)).decision.state == "BLOCK"

    def test_a_served_allow_records_each_shortfall_it_stood_in_for(self, tmp_path: Path) -> None:
        answer = self.served(tmp_path, None, timedelta(hours=3))
        assert answer.source == "remembered" and answer.decision.state == "ALLOW"
        recorded = [
            (item.code, item.setting, item.level, item.environment)
            for item in answer.decision.relaxations or ()
        ]
        assert recorded == [("R201", "serve_last_allow", "allow", "production")]

    def test_the_decision_served_is_valid_against_the_decision_contract(
        self, tmp_path: Path
    ) -> None:
        from cordon_scanner.contracts.schema_check import SchemaChecker
        from cordon_scanner.contracts.schemas import ContractSchemas

        answer = self.served(tmp_path, None, timedelta(hours=3))
        assert (
            SchemaChecker.errors(ContractSchemas.load("decision-v1"), answer.decision.to_json())
            == []
        )
