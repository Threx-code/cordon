"""The provenance detector's test kit: a registry answer and a verifier substituted, so a test of
what the detector orchestrates needs no network and no crypto stack. Shared by the provenance and
workload-image tests, imported as a kit rather than one test module importing another (which
depends on the order pytest collects them in, and failed under xdist)."""

from __future__ import annotations

import pytest

from cordon_scanner.detect.base import GraphUnit, ScanContext
from cordon_scanner.detect.supply.provenance import (
    ProvenanceDetector,
)
from cordon_scanner.foundation.config.settings import Config
from cordon_scanner.foundation.models import Scope
from cordon_scanner.foundation.results import Dependency
from cordon_scanner.intel.provenance import attest
from cordon_scanner.intel.provenance.attest import Outcome, Result
from cordon_scanner.intel.registries.registry_client import PackageFacts
from cordon_scanner.rules.loader import RuleLoader, RuleSet

_INTEGRITY = "sha256:" + "ab" * 32


class ProvenanceHelpers:
    """Helpers for test_provenance.py."""

    @staticmethod
    def dependency(
        *,
        ecosystem: str = "npm",
        integrity: str | None = _INTEGRITY,
        version: str | None = "1.0.0",
    ) -> Dependency:
        return Dependency(
            purl=f"pkg:{ecosystem}/example@{version}",
            ecosystem=ecosystem,
            name="example",
            version=version,
            direct=True,
            scope=Scope.RUNTIME,
            integrity=integrity,
            declared_in="package-lock.json",
        )

    @staticmethod
    def context(*, offline: bool = False) -> ScanContext:
        return ScanContext(
            config=Config.default(),
            rules=RuleSet(RuleLoader.load_builtin()),
            offline=offline,
        )

    @staticmethod
    def ids(dep: Dependency, ctx: ScanContext | None = None) -> list[str]:
        ctx = ctx or ProvenanceHelpers.context()
        return [
            f.rule_id for f in ProvenanceDetector().inspect(GraphUnit(dependencies=(dep,)), ctx)
        ]

    @staticmethod
    def _attested(repository: str | None = "https://github.com/Owner/Repo") -> PackageFacts:
        return PackageFacts(name="example", version="1.0.0", repository=repository, attested=True)


class ProvenanceFixtures:
    """Fixtures for the tests in test_provenance.py; every test class here inherits them."""

    @pytest.fixture
    def wire(self, monkeypatch):
        """Install a registry answer, a bundle list and a verifier outcome."""

        def install(
            *,
            facts: PackageFacts | Exception,
            bundles: tuple[str, ...] = (),
            outcome: Outcome | None = None,
            available: bool = True,
        ) -> None:
            def fake_facts(ecosystem, name, version):
                if isinstance(facts, Exception):
                    raise facts
                return facts

            monkeypatch.setattr(
                "cordon_scanner.intel.registries.registry_client.RegistryClient.facts", fake_facts
            )
            monkeypatch.setattr(
                "cordon_scanner.intel.registries.registry_client.RegistryClient.attestation_payload",
                lambda ecosystem, name, version, digest=None: (
                    {"attestations": []} if bundles else None
                ),
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


__all__ = ["_INTEGRITY", "ProvenanceFixtures", "ProvenanceHelpers"]
