"""The online enrichment, tested without a network.

Nothing here makes a request. The client is substituted, because a test that
reaches PyPI is a test that fails when PyPI is slow, and a security suite that
people learn to rerun until it passes is worse than no suite.

What is worth testing is the discipline around the answers rather than the
answers themselves: that the detector does not run offline, that an unreachable
registry is reported instead of read as "nothing wrong", and that a missing hash
on either side is not treated as a contradiction.
"""

from __future__ import annotations

import pytest

from cordon_scanner.core.config import Config
from cordon_scanner.core.models import Category, Dependency, Scope, Severity
from cordon_scanner.detect.base import GraphUnit, ScanContext
from cordon_scanner.detect.registry import RegistryDetector
from cordon_scanner.intel.registry_client import PackageFacts, RegistryError
from cordon_scanner.rules.loader import RuleLoader, RuleSet


def dependency(
    name: str = "example",
    version: str | None = "1.0.0",
    *,
    ecosystem: str = "pypi",
    integrity: str | None = None,
) -> Dependency:
    return Dependency(
        purl=f"pkg:{ecosystem}/{name}@{version}",
        ecosystem=ecosystem,
        name=name,
        version=version,
        direct=True,
        scope=Scope.RUNTIME,
        integrity=integrity,
        declared_in="poetry.lock",
    )


def context(*, offline: bool = False) -> ScanContext:
    return ScanContext(
        config=Config.default(),
        rules=RuleSet(RuleLoader.load_builtin()),
        offline=offline,
    )


@pytest.fixture
def answer(monkeypatch):
    """Substitute the registry with a fixed answer."""

    def install(facts: PackageFacts | Exception) -> None:
        def fake(ecosystem: str, name: str, version: str | None):
            if isinstance(facts, Exception):
                raise facts
            return facts

        monkeypatch.setattr("cordon_scanner.intel.registry_client.facts", fake)

    return install


def ids_for(dep: Dependency, ctx: ScanContext | None = None) -> list[str]:
    ctx = ctx or context()
    return [f.rule_id for f in RegistryDetector().inspect(GraphUnit(dependencies=(dep,)), ctx)]


class TestOfflineIsTheDefault:
    def test_it_does_not_run_offline(self, answer) -> None:
        answer(PackageFacts(name="example", version="1.0.0", yanked=True))
        assert ids_for(dependency(), context(offline=True)) == []

    def test_it_is_not_applicable_offline(self) -> None:
        ctx = ScanContext(
            config=Config.default(),
            rules=RuleSet(RuleLoader.load_builtin()),
            dependencies=(dependency(),),
            offline=True,
        )
        assert RegistryDetector().applicable(ctx) is False


class TestWithdrawal:
    def test_a_yanked_version_is_reported(self, answer) -> None:
        answer(
            PackageFacts(
                name="example", version="1.0.0", yanked=True, yanked_reason="malicious release"
            )
        )
        assert "SUSPECT.DEPENDENCY.YANKED.001" in ids_for(dependency())

    def test_a_live_version_is_not(self, answer) -> None:
        answer(PackageFacts(name="example", version="1.0.0", latest="1.0.0"))
        assert ids_for(dependency()) == []


class TestIntegrity:
    def test_a_contradicted_hash_is_critical(self, answer) -> None:
        answer(PackageFacts(name="example", version="1.0.0", digests=("bbbb",)))
        findings = RegistryDetector().inspect(
            GraphUnit(dependencies=(dependency(integrity="sha256:aaaa"),)), context()
        )
        mismatch = [f for f in findings if f.rule_id == "SUSPECT.PROVENANCE.MISMATCH.001"]
        assert mismatch
        assert mismatch[0].severity is Severity.CRITICAL

    def test_matching_hashes_are_silent(self, answer) -> None:
        answer(PackageFacts(name="example", version="1.0.0", digests=("aaaa",)))
        assert "SUSPECT.PROVENANCE.MISMATCH.001" not in ids_for(dependency(integrity="sha256:aaaa"))

    def test_framing_differences_are_not_conflicts(self, answer) -> None:
        """Lockfiles write `sha256-<b64>`, `sha256:<hex>` or a bare digest. The
        framing differs by tool and says nothing about the artefact."""
        answer(PackageFacts(name="example", version="1.0.0", digests=("sha512-Zm9v",)))
        assert "SUSPECT.PROVENANCE.MISMATCH.001" not in ids_for(dependency(integrity="sha512:Zm9v"))

    def test_an_absent_hash_is_not_a_conflict(self, answer) -> None:
        """A lockfile with no hash is already reported by the offline integrity
        rule, and a registry publishing none cannot contradict anything.
        Treating either as a mismatch would fire on the ordinary case and mean
        nothing on the real one."""
        answer(PackageFacts(name="example", version="1.0.0", digests=()))
        assert "SUSPECT.PROVENANCE.MISMATCH.001" not in ids_for(dependency(integrity="sha256:aaaa"))
        answer(PackageFacts(name="example", version="1.0.0", digests=("aaaa",)))
        assert "SUSPECT.PROVENANCE.MISMATCH.001" not in ids_for(dependency(integrity=None))


class TestDistance:
    def test_a_far_behind_pin_is_noted(self, answer) -> None:
        answer(PackageFacts(name="example", version="1.0.0", latest="4.2.0"))
        assert "POLICY.DEPENDENCY.DOWNGRADE.001" in ids_for(dependency())

    def test_one_major_behind_is_ordinary(self, answer) -> None:
        answer(PackageFacts(name="example", version="1.0.0", latest="2.0.0"))
        assert "POLICY.DEPENDENCY.DOWNGRADE.001" not in ids_for(dependency())

    def test_an_unparseable_version_does_not_guess(self, answer) -> None:
        answer(PackageFacts(name="example", version="2024-final", latest="4.0.0"))
        assert "POLICY.DEPENDENCY.DOWNGRADE.001" not in ids_for(dependency(version="2024-final"))


class TestUnansweredQuestions:
    def test_an_unreachable_registry_is_reported(self, answer) -> None:
        """ "We could not ask" and "the answer was no" are different facts, and
        only one of them means there is nothing to worry about."""
        answer(RegistryError("URLError asking pypi.org"))
        found = ids_for(dependency())
        assert found == ["OPERATIONAL.REGISTRY.UNREACHABLE.001"]

    def test_that_report_cannot_be_hidden_by_a_threshold(self, answer) -> None:
        answer(RegistryError("URLError asking pypi.org"))
        findings = list(
            RegistryDetector().inspect(GraphUnit(dependencies=(dependency(),)), context())
        )
        assert findings[0].always_report is True
        assert findings[0].category is Category.OPERATIONAL

    def test_failures_are_aggregated(self, answer) -> None:
        """One finding, not one per package: an offline runner would otherwise
        produce a finding for every dependency in the graph."""
        answer(RegistryError("URLError asking pypi.org"))
        deps = tuple(dependency(f"pkg{i}") for i in range(20))
        findings = list(RegistryDetector().inspect(GraphUnit(dependencies=deps), context()))
        assert len(findings) == 1
        assert "20 package(s)" in findings[0].message


class TestTheNetworkCaveat:
    def test_every_finding_says_where_its_answer_came_from(self, answer) -> None:
        """Rerun offline and it disappears; rerun next week and it may differ.
        A report that did not say so would claim a reproducibility it does not
        have."""
        answer(PackageFacts(name="example", version="1.0.0", yanked=True))
        findings = list(
            RegistryDetector().inspect(GraphUnit(dependencies=(dependency(),)), context())
        )
        assert findings
        for finding in findings:
            assert any("registry query" in note for note in finding.explanation.escalations)
