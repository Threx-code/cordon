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
                "cordon_scanner.intel.registry_client.RegistryClient.facts", fake_facts
            )
            monkeypatch.setattr(
                "cordon_scanner.intel.registry_client.RegistryClient.attestation_payload",
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


class TestItStaysSilentWhereItShould(ProvenanceFixtures):
    def test_offline_runs_nothing(self, wire) -> None:
        wire(facts=ProvenanceHelpers._attested())
        assert (
            ProvenanceHelpers.ids(
                ProvenanceHelpers.dependency(), ProvenanceHelpers.context(offline=True)
            )
            == []
        )

    def test_a_non_graph_unit_is_ignored(self) -> None:
        from cordon_scanner.core.content import FileContent
        from cordon_scanner.detect.base import FileUnit

        unit = FileUnit(content=FileContent.from_bytes("a.py", b"x = 1\n"), language="python")
        assert list(ProvenanceDetector().inspect(unit, ProvenanceHelpers.context())) == []

    def test_a_package_with_no_attestation_is_ignored(self, wire) -> None:
        wire(facts=PackageFacts(name="example", version="1.0.0", attested=False))
        assert ProvenanceHelpers.ids(ProvenanceHelpers.dependency()) == []

    def test_an_unsupported_ecosystem_is_ignored(self, wire) -> None:
        wire(facts=ProvenanceHelpers._attested())
        assert ProvenanceHelpers.ids(ProvenanceHelpers.dependency(ecosystem="cargo")) == []

    def test_an_unreachable_registry_is_left_to_the_registry_detector(self, wire) -> None:
        wire(facts=RegistryError("timeout"))
        assert ProvenanceHelpers.ids(ProvenanceHelpers.dependency()) == []

    @pytest.mark.conformance("x", "x.provenance")
    def test_a_verified_attestation_produces_no_finding(self, wire) -> None:
        wire(facts=ProvenanceHelpers._attested(), bundles=("{}",), outcome=Outcome.VERIFIED)
        assert ProvenanceHelpers.ids(ProvenanceHelpers.dependency()) == []


class TestItReportsWhatItCannotProve(ProvenanceFixtures):
    def test_a_missing_pinned_digest_is_unverified(self, wire) -> None:
        wire(facts=ProvenanceHelpers._attested())
        assert ProvenanceHelpers.ids(ProvenanceHelpers.dependency(integrity=None)) == [
            UNVERIFIED_RULE
        ]

    def test_the_extra_absent_is_unverified(self, wire) -> None:
        wire(facts=ProvenanceHelpers._attested(), bundles=(), available=False)
        assert ProvenanceHelpers.ids(ProvenanceHelpers.dependency()) == [UNVERIFIED_RULE]

    def test_no_usable_bundle_is_unverified(self, wire) -> None:
        wire(facts=ProvenanceHelpers._attested(), bundles=(), available=True)
        assert ProvenanceHelpers.ids(ProvenanceHelpers.dependency()) == [UNVERIFIED_RULE]

    def test_an_unverifiable_outcome_is_unverified(self, wire) -> None:
        wire(facts=ProvenanceHelpers._attested(), bundles=("{}",), outcome=Outcome.UNVERIFIABLE)
        assert ProvenanceHelpers.ids(ProvenanceHelpers.dependency()) == [UNVERIFIED_RULE]


class TestItReportsAFailedVerification(ProvenanceFixtures):
    @pytest.mark.conformance("x", "x.provenance")
    def test_an_invalid_bundle_is_a_vulnerability(self, wire) -> None:
        wire(facts=ProvenanceHelpers._attested(), bundles=("{}",), outcome=Outcome.INVALID)
        assert ProvenanceHelpers.ids(ProvenanceHelpers.dependency()) == [INVALID_RULE]

    @pytest.mark.conformance("x", "x.provenance")
    def test_the_declared_repository_case_is_preserved(self, wire, monkeypatch) -> None:
        # The OIDC repository claim keeps the stored case, so the identity passed
        # to the verifier must not be lowercased by the mismatch helper.
        seen: dict[str, object] = {}

        def spy(*a, **k):
            seen["source_repo"] = k.get("source_repo")
            return Result(Outcome.VERIFIED, "ok")

        monkeypatch.setattr(
            "cordon_scanner.intel.registry_client.RegistryClient.facts",
            lambda *a: ProvenanceHelpers._attested(),
        )
        monkeypatch.setattr(
            "cordon_scanner.intel.registry_client.RegistryClient.attestation_payload",
            lambda *a: {"attestations": []},
        )
        monkeypatch.setattr(attest.AttestationDocuments, "extract_bundles", lambda *a: ("{}",))
        monkeypatch.setattr(attest.SigstoreVerification, "available", lambda: True)
        monkeypatch.setattr(attest.SigstoreVerification, "verify", spy)

        ProvenanceHelpers.ids(ProvenanceHelpers.dependency())
        assert seen["source_repo"] == ("github.com", "Owner", "Repo")


class OwnVerifiers:
    """Stand-ins for the Bazel and Helm verifiers: what each was asked, how often a keyring was
    read, and the outcome every check answers."""

    def __init__(self, monkeypatch) -> None:
        from cordon_scanner.intel.bazel_provenance import BazelProvenance, ModuleCheck
        from cordon_scanner.intel.helm_provenance import ChartCheck, HelmProvenance
        from cordon_scanner.intel.openpgp import Keyring, OpenPgp

        self.modules: list[str] = []
        self.charts: list[tuple[str, str | None, tuple[str, ...]]] = []
        self.keyring_reads: list[tuple[str, ...]] = []
        self.outcome = "verified"

        def load(paths: tuple[str, ...]) -> Keyring:
            self.keyring_reads.append(paths)
            return Keyring(paths=paths)

        def module(name, version, integrity):
            self.modules.append(name)
            return ModuleCheck(self.outcome, "stood in")

        def chart(name, version, source, integrity, keyring):
            self.charts.append((name, source, keyring.paths))
            return ChartCheck(self.outcome, "stood in")

        monkeypatch.setattr(attest.SigstoreVerification, "available", lambda: True)
        monkeypatch.setattr(OpenPgp, "available", staticmethod(lambda: True))
        monkeypatch.setattr(OpenPgp, "load", staticmethod(load))
        monkeypatch.setattr(BazelProvenance, "check", staticmethod(module))
        monkeypatch.setattr(HelmProvenance, "check", staticmethod(chart))


class TestTheEcosystemsVerifiedOutsideTheRegistryClient:
    """Bazel modules and Helm charts are verified by their own modules: which dependencies reach
    them, and what each of their answers becomes."""

    @staticmethod
    def dependency(ecosystem: str, name: str, resolved_from: str | None) -> Dependency:
        return Dependency(
            purl=f"pkg:{ecosystem}/{name}@1.0.0",
            ecosystem=ecosystem,
            name=name,
            version="1.0.0",
            direct=True,
            resolved_from=resolved_from,
            integrity=_INTEGRITY,
            declared_in="Chart.lock" if ecosystem == "helm" else "MODULE.bazel.lock",
        )

    @staticmethod
    def run(deps: tuple[Dependency, ...], keyrings: tuple[str, ...] = ()) -> list[str]:
        from dataclasses import replace

        ctx = ScanContext(
            config=replace(Config.default(), keyrings=keyrings),
            rules=RuleSet(RuleLoader.load_builtin()),
            offline=False,
        )
        return [f.rule_id for f in ProvenanceDetector().inspect(GraphUnit(dependencies=deps), ctx)]

    def test_only_charts_from_a_repository_are_asked_and_the_keyring_is_read_once(
        self, monkeypatch
    ) -> None:
        stand_in = OwnVerifiers(monkeypatch)
        deps = (
            self.dependency("helm", "a", "https://charts.example.invalid"),
            self.dependency("helm", "b", "oci://registry.example.invalid/charts"),
            self.dependency("helm", "c", "registry:internal"),
            self.dependency("helm", "d", None),
        )
        assert self.run(deps, ("/keys/ring.asc",)) == []
        assert [name for name, _, _ in stand_in.charts] == ["a", "b"]
        assert {paths for _, _, paths in stand_in.charts} == {("/keys/ring.asc",)}
        assert stand_in.keyring_reads == [("/keys/ring.asc",)]

    def test_only_bcr_modules_are_asked(self, monkeypatch) -> None:
        stand_in = OwnVerifiers(monkeypatch)
        self.run(
            (
                self.dependency("bazel", "rules_x", None),
                self.dependency("bazel", "rules_y", "https://registry.example.invalid/"),
                self.dependency("bazel", "com.example:lib", None),
            )
        )
        assert stand_in.modules == ["rules_x"]

    @pytest.mark.parametrize(
        ("outcome", "rules"),
        [
            ("verified", []),
            ("absent", []),
            ("invalid", [INVALID_RULE]),
            ("unverifiable", [UNVERIFIED_RULE]),
            ("unconfigured", [UNVERIFIED_RULE]),
        ],
    )
    def test_each_chart_answer_becomes_its_rule(self, monkeypatch, outcome, rules) -> None:
        stand_in = OwnVerifiers(monkeypatch)
        stand_in.outcome = outcome
        assert self.run((self.dependency("helm", "a", "https://charts.example.invalid"),)) == rules

    @pytest.mark.parametrize(
        ("outcome", "rules"),
        [
            ("verified", []),
            ("absent", []),
            ("invalid", [INVALID_RULE]),
            ("unverifiable", [UNVERIFIED_RULE]),
            ("unpinned", [UNVERIFIED_RULE]),
        ],
    )
    def test_each_module_answer_becomes_its_rule(self, monkeypatch, outcome, rules) -> None:
        stand_in = OwnVerifiers(monkeypatch)
        stand_in.outcome = outcome
        assert self.run((self.dependency("bazel", "rules_x", None),)) == rules


class TestAnsibleCollectionsReachTheirVerifier:
    """Which Ansible dependencies are checked, and how: the signatures an install recorded, over
    the MANIFEST.json in the tree; else galaxy.ansible.com's, for one exact version from there."""

    @staticmethod
    def dependency(**fields: object) -> Dependency:
        base: dict[str, object] = {
            "purl": "pkg:ansible/demo.signed@1.0.0",
            "ecosystem": "ansible",
            "name": "demo.signed",
            "version": "1.0.0",
            "direct": True,
            "declared_in": "requirements.yml",
        }
        base.update(fields)
        return Dependency(**base)  # type: ignore[arg-type]

    @pytest.fixture
    def asked(self, monkeypatch) -> list[tuple[str, object]]:
        from cordon_scanner.intel.ansible_signatures import AnsibleSignatures, CollectionCheck
        from cordon_scanner.intel.openpgp import Keyring, OpenPgp

        asked: list[tuple[str, object]] = []

        def installed(name, version, manifest, signatures, keyring):
            asked.append(("installed", manifest))
            return CollectionCheck("invalid", "stood in")

        def remote(name, version, sources, keyring):
            asked.append(("remote", sources))
            return CollectionCheck("verified", "stood in")

        monkeypatch.setattr(OpenPgp, "available", staticmethod(lambda: True))
        monkeypatch.setattr(OpenPgp, "load", staticmethod(lambda paths: Keyring(paths=paths)))
        monkeypatch.setattr(AnsibleSignatures, "installed", staticmethod(installed))
        monkeypatch.setattr(AnsibleSignatures, "remote", staticmethod(remote))
        return asked

    def test_recorded_signatures_are_checked_over_the_installed_manifest(self, asked) -> None:
        rules = TestTheEcosystemsVerifiedOutsideTheRegistryClient.run(
            (self.dependency(signatures=("sig",), signed=b"{}"),)
        )
        assert asked == [("installed", b"{}")]
        assert rules == [INVALID_RULE]

    def test_a_galaxy_collection_is_checked_with_its_requirements_signatures(self, asked) -> None:
        rules = TestTheEcosystemsVerifiedOutsideTheRegistryClient.run(
            (self.dependency(signature_sources=("https://s.example.invalid/a.asc",)),)
        )
        assert asked == [("remote", ("https://s.example.invalid/a.asc",))]
        assert rules == []

    def test_a_git_source_or_an_unpinned_one_is_not_asked(self, asked) -> None:
        TestTheEcosystemsVerifiedOutsideTheRegistryClient.run(
            (
                self.dependency(resolved_from="git+https://github.com/x/y.git#v1"),
                self.dependency(version=None),
            )
        )
        assert asked == []

    def test_signatures_for_an_artifact_off_galaxy_are_reported_unverified(self, asked) -> None:
        rules = TestTheEcosystemsVerifiedOutsideTheRegistryClient.run(
            (
                self.dependency(
                    resolved_from="registry:hub.example.invalid",
                    signature_sources=("https://s.example.invalid/a.asc",),
                ),
            )
        )
        assert asked == []
        assert rules == [UNVERIFIED_RULE]
