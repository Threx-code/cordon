"""The provenance detector, tested without a network or the crypto stack.

The registry answer and the verifier are both substituted, because what this
detector owns is the orchestration, not the maths: it stays silent offline and
on a package with no attestation, it reports the difference between "could not
verify" (`POLICY.PROVENANCE.UNVERIFIED`) and "verified and failed"
(`VULNERABLE.PROVENANCE.INVALID`), and a verified attestation produces no
finding at all.
"""

from __future__ import annotations

import pytest

from cordon_scanner.core.config import Config
from cordon_scanner.core.models import Dependency, Scope
from cordon_scanner.detect.base import GraphUnit, ScanContext
from cordon_scanner.detect.provenance import INVALID_RULE, UNVERIFIED_RULE, ProvenanceDetector
from cordon_scanner.intel import attest
from cordon_scanner.intel.attest import Outcome, Result
from cordon_scanner.intel.registry_client import PackageFacts, RegistryError
from cordon_scanner.rules.loader import RuleLoader, RuleSet

_INTEGRITY = "sha256:" + "ab" * 32


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


def context(*, offline: bool = False) -> ScanContext:
    return ScanContext(
        config=Config.default(),
        rules=RuleSet(RuleLoader.load_builtin()),
        offline=offline,
    )


@pytest.fixture
def wire(monkeypatch):
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

        monkeypatch.setattr("cordon_scanner.intel.registry_client.facts", fake_facts)
        monkeypatch.setattr(
            "cordon_scanner.intel.registry_client.attestation_payload",
            lambda ecosystem, name, version: {"attestations": []} if bundles else None,
        )
        monkeypatch.setattr(attest, "extract_bundles", lambda ecosystem, payload: bundles)
        monkeypatch.setattr(attest, "available", lambda: available)
        if outcome is not None:
            monkeypatch.setattr(
                attest, "verify", lambda *a, **k: Result(outcome, f"stub {outcome.value}")
            )

    return install


def ids(dep: Dependency, ctx: ScanContext | None = None) -> list[str]:
    ctx = ctx or context()
    return [f.rule_id for f in ProvenanceDetector().inspect(GraphUnit(dependencies=(dep,)), ctx)]


def _attested(repository: str | None = "https://github.com/Owner/Repo") -> PackageFacts:
    return PackageFacts(name="example", version="1.0.0", repository=repository, attested=True)


class TestItStaysSilentWhereItShould:
    def test_offline_runs_nothing(self, wire) -> None:
        wire(facts=_attested())
        assert ids(dependency(), context(offline=True)) == []

    def test_a_non_graph_unit_is_ignored(self) -> None:
        from cordon_scanner.core.content import FileContent
        from cordon_scanner.detect.base import FileUnit

        unit = FileUnit(content=FileContent.from_bytes("a.py", b"x = 1\n"), language="python")
        assert list(ProvenanceDetector().inspect(unit, context())) == []

    def test_a_package_with_no_attestation_is_ignored(self, wire) -> None:
        wire(facts=PackageFacts(name="example", version="1.0.0", attested=False))
        assert ids(dependency()) == []

    def test_an_unsupported_ecosystem_is_ignored(self, wire) -> None:
        wire(facts=_attested())
        assert ids(dependency(ecosystem="cargo")) == []

    def test_an_unreachable_registry_is_left_to_the_registry_detector(self, wire) -> None:
        wire(facts=RegistryError("timeout"))
        assert ids(dependency()) == []

    def test_a_verified_attestation_produces_no_finding(self, wire) -> None:
        wire(facts=_attested(), bundles=("{}",), outcome=Outcome.VERIFIED)
        assert ids(dependency()) == []


class TestItReportsWhatItCannotProve:
    def test_a_missing_pinned_digest_is_unverified(self, wire) -> None:
        wire(facts=_attested())
        assert ids(dependency(integrity=None)) == [UNVERIFIED_RULE]

    def test_the_extra_absent_is_unverified(self, wire) -> None:
        wire(facts=_attested(), bundles=(), available=False)
        assert ids(dependency()) == [UNVERIFIED_RULE]

    def test_no_usable_bundle_is_unverified(self, wire) -> None:
        wire(facts=_attested(), bundles=(), available=True)
        assert ids(dependency()) == [UNVERIFIED_RULE]

    def test_an_unverifiable_outcome_is_unverified(self, wire) -> None:
        wire(facts=_attested(), bundles=("{}",), outcome=Outcome.UNVERIFIABLE)
        assert ids(dependency()) == [UNVERIFIED_RULE]


class TestItReportsAFailedVerification:
    def test_an_invalid_bundle_is_a_vulnerability(self, wire) -> None:
        wire(facts=_attested(), bundles=("{}",), outcome=Outcome.INVALID)
        assert ids(dependency()) == [INVALID_RULE]

    def test_the_declared_repository_case_is_preserved(self, wire, monkeypatch) -> None:
        # The OIDC repository claim keeps the stored case, so the identity passed
        # to the verifier must not be lowercased by the mismatch helper.
        seen: dict[str, object] = {}

        def spy(*a, **k):
            seen["source_repo"] = k.get("source_repo")
            return Result(Outcome.VERIFIED, "ok")

        monkeypatch.setattr("cordon_scanner.intel.registry_client.facts", lambda *a: _attested())
        monkeypatch.setattr(
            "cordon_scanner.intel.registry_client.attestation_payload",
            lambda *a: {"attestations": []},
        )
        monkeypatch.setattr(attest, "extract_bundles", lambda *a: ("{}",))
        monkeypatch.setattr(attest, "available", lambda: True)
        monkeypatch.setattr(attest, "verify", spy)

        ids(dependency())
        assert seen["source_repo"] == ("github.com", "Owner", "Repo")
