"""The rules that say a check did not run.

Five rules had no test and no corpus sample naming them anywhere. They are the
ones that report the scan's own limits -- a registry that could not be asked, a
graph that ran past a query ceiling, an attestation that could not be bound to
an artefact -- and they matter more than their severity suggests: each exists so
that "nothing was reported" is distinguishable from "nothing was checked". A
scan that loses one of them looks cleaner than a scan that has it.

Nothing here makes a request. The registry client and the attestation verifier
are substituted, for the reason `test_registry_detector.py` gives: a test that
reaches PyPI is a test that fails when PyPI is slow.
"""

from __future__ import annotations

import pytest

from cordon_scanner.core.config import Config
from cordon_scanner.core.models import Dependency, Scope
from cordon_scanner.detect.base import GraphUnit, ScanContext
from cordon_scanner.detect.provenance import (
    INVALID_RULE,
    UNCHECKED_RULE,
    UNVERIFIED_RULE,
    ProvenanceDetector,
)
from cordon_scanner.detect.registry import MAX_QUERIES, RegistryDetector
from cordon_scanner.intel import attest
from cordon_scanner.intel.attest import Outcome, Result
from cordon_scanner.intel.registry_client import PackageFacts
from cordon_scanner.rules.loader import RuleLoader, RuleSet

_INTEGRITY = "sha256:" + "ab" * 32


class CoverageNoticesHelpers:
    """Helpers for test_coverage_notices.py."""

    @staticmethod
    def dependency(
        name: str = "example",
        *,
        ecosystem: str = "npm",
        integrity: str | None = _INTEGRITY,
    ) -> Dependency:
        return Dependency(
            purl=f"pkg:{ecosystem}/{name}@1.0.0",
            ecosystem=ecosystem,
            name=name,
            version="1.0.0",
            direct=True,
            scope=Scope.RUNTIME,
            integrity=integrity,
            declared_in="package-lock.json",
        )

    @staticmethod
    def context() -> ScanContext:
        return ScanContext(
            config=Config.default(), rules=RuleSet(RuleLoader.load_builtin()), offline=False
        )

    @staticmethod
    def registry_ids(deps: tuple[Dependency, ...], ctx: ScanContext | None = None) -> list[str]:
        ctx = ctx or CoverageNoticesHelpers.context()
        return [f.rule_id for f in RegistryDetector().inspect(GraphUnit(dependencies=deps), ctx)]

    @staticmethod
    def provenance_ids(deps: tuple[Dependency, ...], ctx: ScanContext | None = None) -> list[str]:
        ctx = ctx or CoverageNoticesHelpers.context()
        return [f.rule_id for f in ProvenanceDetector().inspect(GraphUnit(dependencies=deps), ctx)]


class CoverageNoticesFixtures:
    """Fixtures for the tests in test_coverage_notices.py; every test class here inherits them."""

    @pytest.fixture
    def registry(self, monkeypatch):
        def install(facts: PackageFacts | Exception) -> None:
            def fake(ecosystem, name, version):
                if isinstance(facts, Exception):
                    raise facts
                return facts

            monkeypatch.setattr("cordon_scanner.intel.registry_client.RegistryClient.facts", fake)

        return install

    @pytest.fixture
    def provenance(self, monkeypatch):
        def install(
            *,
            facts: PackageFacts,
            bundles: tuple[str, ...] = (),
            outcome: Outcome | None = None,
            available: bool = True,
        ) -> None:
            monkeypatch.setattr(
                "cordon_scanner.intel.registry_client.RegistryClient.facts",
                lambda ecosystem, name, version: facts,
            )
            monkeypatch.setattr(
                "cordon_scanner.intel.registry_client.RegistryClient.attestation_payload",
                lambda ecosystem, name, version: {"attestations": []} if bundles else None,
            )
            monkeypatch.setattr(
                attest.AttestationDocuments, "extract_bundles", lambda ecosystem, payload: bundles
            )
            monkeypatch.setattr(attest.SigstoreVerification, "available", lambda: available)
            if outcome is not None:
                monkeypatch.setattr(
                    attest.SigstoreVerification,
                    "verify",
                    lambda *a, **k: Result(outcome, f"stub {outcome.value}"),
                )

        return install


class TestWhatWasNotAsked(CoverageNoticesFixtures):
    """`--online` asks ten registries. Everything else in the graph (Conan, CocoaPods, Swift,
    CRAN, conda) is unexamined, and the difference between that and clean is the whole point of the
    rule."""

    def test_an_ecosystem_with_no_registry_is_reported(self, registry) -> None:
        registry(PackageFacts(name="example", version="1.0.0"))
        found = CoverageNoticesHelpers.registry_ids(
            (
                CoverageNoticesHelpers.dependency(ecosystem="conan"),
                CoverageNoticesHelpers.dependency(ecosystem="swift"),
            )
        )
        assert "OPERATIONAL.REGISTRY.NO_SOURCE.001" in found

    def test_an_ecosystem_that_is_asked_is_not_reported(self, registry) -> None:
        registry(PackageFacts(name="example", version="1.0.0"))
        found = CoverageNoticesHelpers.registry_ids(
            (
                CoverageNoticesHelpers.dependency(ecosystem="npm"),
                CoverageNoticesHelpers.dependency(ecosystem="pypi"),
            )
        )
        assert "OPERATIONAL.REGISTRY.NO_SOURCE.001" not in found

    def test_the_query_ceiling_is_reported(self, registry) -> None:
        registry(PackageFacts(name="example", version="1.0.0"))
        many = tuple(CoverageNoticesHelpers.dependency(f"pkg{n}") for n in range(MAX_QUERIES + 5))
        assert "OPERATIONAL.REGISTRY.NOT_ASKED.001" in CoverageNoticesHelpers.registry_ids(many)

    def test_a_graph_inside_the_ceiling_is_not(self, registry) -> None:
        registry(PackageFacts(name="example", version="1.0.0"))
        few = tuple(CoverageNoticesHelpers.dependency(f"pkg{n}") for n in range(5))
        assert "OPERATIONAL.REGISTRY.NOT_ASKED.001" not in CoverageNoticesHelpers.registry_ids(few)

    def test_the_notice_degrades_coverage(self, registry) -> None:
        """A scan that stopped asking must not report `complete: true`."""
        registry(PackageFacts(name="example", version="1.0.0"))
        many = tuple(CoverageNoticesHelpers.dependency(f"pkg{n}") for n in range(MAX_QUERIES + 5))
        findings = RegistryDetector().inspect(
            GraphUnit(dependencies=many), CoverageNoticesHelpers.context()
        )
        notice = next(f for f in findings if f.rule_id == "OPERATIONAL.REGISTRY.NOT_ASKED.001")
        assert notice.degrades_coverage


class TestProvenanceThatCouldNotBeSettled(CoverageNoticesFixtures):
    ATTESTED = PackageFacts(
        name="example", version="1.0.0", repository="https://github.com/Owner/Repo", attested=True
    )

    def test_a_package_past_the_ceiling_is_reported_unchecked(self, provenance) -> None:
        provenance(facts=self.ATTESTED, bundles=("bundle",), outcome=Outcome.VERIFIED)
        many = tuple(CoverageNoticesHelpers.dependency(f"pkg{n}") for n in range(MAX_QUERIES + 3))
        assert UNCHECKED_RULE in CoverageNoticesHelpers.provenance_ids(many)

    def test_a_graph_inside_the_ceiling_is_not(self, provenance) -> None:
        provenance(facts=self.ATTESTED, bundles=("bundle",), outcome=Outcome.VERIFIED)
        assert UNCHECKED_RULE not in CoverageNoticesHelpers.provenance_ids(
            (CoverageNoticesHelpers.dependency(),)
        )

    def test_an_attestation_with_nothing_to_bind_it_is_unverified(self, provenance) -> None:
        """An attestation says a thing was built somewhere. Without a pinned
        artefact digest there is nothing to say it is about THIS download."""
        provenance(facts=self.ATTESTED, bundles=("bundle",), outcome=Outcome.VERIFIED)
        assert UNVERIFIED_RULE in CoverageNoticesHelpers.provenance_ids(
            (CoverageNoticesHelpers.dependency(integrity=None),)
        )

    def test_an_attestation_the_registry_will_not_serve_is_unverified(self, provenance) -> None:
        provenance(facts=self.ATTESTED, bundles=(), outcome=None)
        assert UNVERIFIED_RULE in CoverageNoticesHelpers.provenance_ids(
            (CoverageNoticesHelpers.dependency(),)
        )

    def test_an_attestation_that_fails_verification_is_invalid(self, provenance) -> None:
        provenance(facts=self.ATTESTED, bundles=("bundle",), outcome=Outcome.INVALID)
        assert INVALID_RULE in CoverageNoticesHelpers.provenance_ids(
            (CoverageNoticesHelpers.dependency(),)
        )

    def test_an_attestation_that_verifies_reports_nothing(self, provenance) -> None:
        """The other half, and the one that keeps the rules above honest."""
        provenance(facts=self.ATTESTED, bundles=("bundle",), outcome=Outcome.VERIFIED)
        assert CoverageNoticesHelpers.provenance_ids((CoverageNoticesHelpers.dependency(),)) == []
