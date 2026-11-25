"""Row BP-3-17: the third-party integration kind: its canonical id, its digest rule (the declared contract) and its resolver."""

from __future__ import annotations

import hashlib
import json

import pytest

from cordon_scanner.contracts.digests import ArtifactDigests
from cordon_scanner.contracts.subjects import CanonicalIds, SubjectKind
from cordon_scanner.decide.resolve.integration import IntegrationResolver

OPENAPI = {
    "openapi": "3.0.3",
    "info": {"title": "Payments", "version": "2.1.0"},
    "paths": {"/charges": {"post": {"summary": "Create a charge"}}},
}


class TestTheContractDigest:
    def test_it_is_the_sha256_of_the_canonical_json(self) -> None:
        by_hand = json.dumps(OPENAPI, sort_keys=True, separators=(",", ":")).encode()
        assert (
            ArtifactDigests.of_contract(OPENAPI) == "sha256:" + hashlib.sha256(by_hand).hexdigest()
        )

    def test_the_order_of_keys_and_the_form_of_the_text_do_not_matter(self) -> None:
        reordered = {"paths": OPENAPI["paths"], "info": OPENAPI["info"], "openapi": "3.0.3"}
        assert ArtifactDigests.of_contract(reordered) == ArtifactDigests.of_contract(OPENAPI)
        composed = {"name": "caf\u00e9"}
        decomposed = {"name": "cafe\u0301"}
        assert ArtifactDigests.of_contract(composed) == ArtifactDigests.of_contract(decomposed)

    def test_a_changed_contract_is_another_artifact(self) -> None:
        changed = json.loads(json.dumps(OPENAPI))
        changed["paths"]["/refunds"] = {"post": {"summary": "Refund"}}
        assert ArtifactDigests.of_contract(changed) != ArtifactDigests.of_contract(OPENAPI)

    @pytest.mark.parametrize("bad", [{}, [], "text", None])
    def test_something_that_is_not_a_document_is_refused(self, bad) -> None:
        with pytest.raises(ValueError):
            ArtifactDigests.of_contract(bad)


class TestTheResolver:
    def test_a_declared_contract_resolves_to_its_digest(self) -> None:
        found = IntegrationResolver.resolve("Stripe", "Payments API", OPENAPI, version="2.1.0")
        assert found.resolved and found.kind == "third_party_integration"
        assert (
            found.subject_id
            == "int:stripe/payments-api"
            == CanonicalIds.canonical_id(
                SubjectKind.THIRD_PARTY_INTEGRATION,
                {"vendor": "stripe", "integration": "payments-api"},
            )
        )
        assert found.digest == ArtifactDigests.of_contract(OPENAPI) and found.version == "2.1.0"

    def test_a_contract_kept_as_the_bytes_served_is_the_digest_of_those_bytes(self) -> None:
        served = b"openapi: 3.0.3\ninfo: {title: Payments}\n"
        assert IntegrationResolver.resolve("stripe", "payments-api", served).digest == (
            ArtifactDigests.of_bytes(served)
        )

    @pytest.mark.parametrize("contract", [None, b"", {}])
    def test_no_contract_is_unresolved_and_fails_closed(self, contract) -> None:
        found = IntegrationResolver.resolve("stripe", "payments-api", contract)
        assert (found.resolved, found.reason, found.digest) == (False, "no_contract", None)
        assert found.evidence().unresolved is True

    def test_a_name_that_is_not_one_is_unparseable(self) -> None:
        found = IntegrationResolver.resolve("a/b", "c", OPENAPI)
        assert (found.resolved, found.reason) == (False, "unparseable")
        assert found.subject_id.startswith("int:unparsed/")


class TestAnIntegrationFixtureResolvesAndDecides:
    """An integration resolves to its contract digest and goes through `decide()` like any other subject: with a contract it is decided on; with none it fails closed, naming the unresolved reason."""

    @staticmethod
    def decide(resolution):
        from datetime import UTC, datetime

        from cordon_scanner.decide.decision.decider import Decider
        from cordon_scanner.decide.decision.evidence import Context, EvidenceSet
        from cordon_scanner.decide.decision.legacy import LegacyBridge
        from cordon_scanner.foundation.config.settings import Config

        table = LegacyBridge.compiled(Config.default().policy)
        evidence = resolution.evidence(EvidenceSet())
        clock = datetime(2026, 11, 23, 12, tzinfo=UTC)
        return Decider.decide(resolution.artifact(), Context("cli", "dev"), table, evidence, clock)

    def test_an_integration_with_a_contract_is_decided_on_its_digest(self) -> None:
        found = IntegrationResolver.resolve("Stripe", "Payments API", OPENAPI, version="2.1.0")
        artifact = found.artifact()
        assert (
            artifact.kind == "third_party_integration"
            and artifact.subject_id == "int:stripe/payments-api"
        )
        decision = self.decide(found)
        assert "R203" not in decision.reason_codes and decision.inputs_digest

    def test_an_integration_with_no_contract_fails_closed_with_the_unresolved_code(self) -> None:
        decision = self.decide(IntegrationResolver.resolve("stripe", "payments-api", None))
        assert decision.blocked and "R203" in decision.reason_codes

    def test_a_changed_contract_is_decided_as_another_artifact(self) -> None:
        a = self.decide(IntegrationResolver.resolve("stripe", "payments-api", OPENAPI))
        b = self.decide(
            IntegrationResolver.resolve(
                "stripe",
                "payments-api",
                {**OPENAPI, "info": {"title": "Payments", "version": "2.2.0"}},
            )
        )
        assert a.inputs_digest != b.inputs_digest
