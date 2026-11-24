"""A decision signed by a delegated decider key verifies offline against the tenant root; an edited one, an undelegated key and a key outside its window do not."""

from __future__ import annotations

import base64
import copy
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from cordon_scanner.cloud.agent.decision_envelope import DecisionEnvelope
from cordon_scanner.cloud.bundle_chain import BundleError, Dsse
from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.decide.decision.compiler import PolicyCompiler
from cordon_scanner.decide.decision.evidence import ArtifactRef, EvidenceSet
from cordon_scanner.decide.decision.outcome import Decision
from cordon_scanner.decide.decision.policy_source import PolicySource
from cordon_scanner.decide.points import PointRuntime
from cordon_scanner.intel.provenance._ed25519_signer import Ed25519Signer
from kits.bundle_kit import T0, TENANT, Kit, Platform

DECIDER = Ed25519Signer(Kit.seed("decider"))
STRANGER = Ed25519Signer(Kit.seed("stranger"))
NOW = T0 + timedelta(hours=1)


class Fixture:
    @staticmethod
    def decision() -> Decision:
        source = {
            "policy_schema": 2,
            "id": "acme/policy",
            "version": 1,
            "scope": ["acme"],
            "rules": [],
            "defaults": {},
        }
        artifact = ArtifactRef(
            kind="package",
            subject_id="pkg:npm/left-pad",
            digest=ArtifactDigests.of_bytes(b"artifact"),
            ecosystem="npm",
            released_at="2026-06-01T00:00:00Z",
        )
        return PointRuntime.ask(
            "cli",
            artifact,
            EvidenceSet(),
            PolicyCompiler.compile(PolicySource.from_json(source)),
            datetime(2026, 11, 24, 10, 0, tzinfo=UTC),
            environment="production",
            scope_path=("acme",),
        )

    @staticmethod
    def delegation(
        platform: Platform, not_before: datetime = T0 - timedelta(days=1)
    ) -> dict[str, Any]:
        document = {
            "_type": "cordon.delegation/v1",
            "tenant": TENANT,
            "issued_at": T0.isoformat(),
            "keys": [
                {
                    "keyid": Dsse.keyid(DECIDER.public),
                    "public": DECIDER.public.hex(),
                    "role": "decider",
                    "not_before": not_before.isoformat(),
                    "version": 1,
                }
            ],
        }
        return Platform.sign("application/vnd.cordon.delegation+json", document, platform.root)

    @staticmethod
    def verify(envelope: object, platform: Platform, delegation: dict[str, Any]) -> dict[str, Any]:
        return DecisionEnvelope.verify(
            envelope,
            root_public=platform.root.public,
            delegation=delegation,
            tenant=TENANT,
            now=NOW,
        )


class TestADecisionSignedByTheDecider:
    def test_it_verifies_offline_and_carries_the_decision(self) -> None:
        platform = Platform()
        decision = Fixture.decision()
        envelope = DecisionEnvelope.sign(decision, DECIDER)
        found = Fixture.verify(envelope, platform, Fixture.delegation(platform))
        assert found["state"] == decision.state

    def test_an_edit_after_signing_is_refused(self) -> None:
        platform = Platform()
        envelope = DecisionEnvelope.sign(Fixture.decision(), DECIDER)
        altered = copy.deepcopy(envelope)
        body = base64.b64decode(altered["payload"]).replace(b"ALLOW", b"BLOCK")
        altered["payload"] = base64.b64encode(body).decode("ascii")
        with pytest.raises(BundleError):
            Fixture.verify(altered, platform, Fixture.delegation(platform))

    def test_a_key_the_root_did_not_delegate_is_refused(self) -> None:
        platform = Platform()
        envelope = DecisionEnvelope.sign(Fixture.decision(), STRANGER)
        with pytest.raises(BundleError):
            Fixture.verify(envelope, platform, Fixture.delegation(platform))

    def test_a_key_before_its_window_is_refused(self) -> None:
        platform = Platform()
        envelope = DecisionEnvelope.sign(Fixture.decision(), DECIDER)
        late = Fixture.delegation(platform, not_before=T0 + timedelta(days=1))
        with pytest.raises(BundleError):
            Fixture.verify(envelope, platform, late)

    def test_a_policy_key_cannot_sign_a_decision(self) -> None:
        platform = Platform()
        envelope = DecisionEnvelope.sign(Fixture.decision(), platform.policy_key)
        with pytest.raises(BundleError):
            Fixture.verify(envelope, platform, platform.delegation())
