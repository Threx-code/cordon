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

import base64
import hashlib
from typing import Any, ClassVar

import pytest

from cordon_scanner.core.config import Config
from cordon_scanner.core.content import FileContent
from cordon_scanner.core.models import Category, Dependency, Scope, Severity
from cordon_scanner.detect.base import FileUnit, GraphUnit, ScanContext
from cordon_scanner.detect.registry import RegistryDetector, RegistryEvidence
from cordon_scanner.intel.registry_client import PackageFacts, RegistryError
from cordon_scanner.rules.loader import RuleLoader, RuleSet


class RegistryDetectorHelpers:
    """Helpers for test_registry_detector.py."""

    @staticmethod
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

    @staticmethod
    def context(*, offline: bool = False) -> ScanContext:
        return ScanContext(
            config=Config.default(),
            rules=RuleSet(RuleLoader.load_builtin()),
            offline=offline,
        )

    @staticmethod
    def ids_for(dep: Dependency, ctx: ScanContext | None = None) -> list[str]:
        ctx = ctx or RegistryDetectorHelpers.context()
        return [f.rule_id for f in RegistryDetector().inspect(GraphUnit(dependencies=(dep,)), ctx)]

    @staticmethod
    def _npm_from(document: dict, name: str, version: str) -> PackageFacts:
        """Run the npm reader against a fixed document, with no request made."""
        import unittest.mock

        from cordon_scanner.intel import registry_client

        with unittest.mock.patch.object(
            registry_client.RegistryClient, "_fetch", return_value=document
        ):
            return registry_client.RegistryClient._npm(name, version)


class RegistryDetectorFixtures:
    """Fixtures for the tests in test_registry_detector.py; every test class here inherits them."""

    @pytest.fixture
    def answer(self, monkeypatch):
        """Substitute the registry with a fixed answer."""

        def install(facts: PackageFacts | Exception) -> None:
            def fake(ecosystem: str, name: str, version: str | None):
                if isinstance(facts, Exception):
                    raise facts
                return facts

            monkeypatch.setattr("cordon_scanner.intel.registry_client.RegistryClient.facts", fake)

        return install


class TestOfflineIsTheDefault(RegistryDetectorFixtures):
    def test_it_does_not_run_offline(self, answer) -> None:
        answer(PackageFacts(name="example", version="1.0.0", yanked=True))
        assert (
            RegistryDetectorHelpers.ids_for(
                RegistryDetectorHelpers.dependency(), RegistryDetectorHelpers.context(offline=True)
            )
            == []
        )

    def test_it_is_not_applicable_offline(self) -> None:
        ctx = ScanContext(
            config=Config.default(),
            rules=RuleSet(RuleLoader.load_builtin()),
            dependencies=(RegistryDetectorHelpers.dependency(),),
            offline=True,
        )
        assert RegistryDetector().applicable(ctx) is False


class TestWithdrawal(RegistryDetectorFixtures):
    def test_a_yanked_version_is_reported(self, answer) -> None:
        answer(
            PackageFacts(
                name="example", version="1.0.0", yanked=True, yanked_reason="malicious release"
            )
        )
        assert "SUSPECT.DEPENDENCY.YANKED.001" in RegistryDetectorHelpers.ids_for(
            RegistryDetectorHelpers.dependency()
        )

    def test_a_live_version_is_not(self, answer) -> None:
        answer(PackageFacts(name="example", version="1.0.0", latest="1.0.0"))
        assert RegistryDetectorHelpers.ids_for(RegistryDetectorHelpers.dependency()) == []


#: Real digests of two different byte strings, in the shapes registries and
#: lockfiles actually publish. Toy values like `"aaaa"` cannot be used here:
#: a string is only compared when its length says it is a digest of the
#: algorithm it names, which is the whole guard against non-digest values.
_BLOB = b"the tarball bytes"
_OTHER = b"different bytes"
SHA256_HEX = hashlib.sha256(_BLOB).hexdigest()
SHA512_SRI = "sha512-" + base64.b64encode(hashlib.sha512(_BLOB).digest()).decode()
# sha1 because npm publishes one: `dist.shasum` sits beside the sha512
# `dist.integrity`, and a lockfile recording either must not contradict the other.
SHA1_HEX = hashlib.sha1(_BLOB).hexdigest()  # noqa: S324
SHA1_SRI = "sha1-" + base64.b64encode(hashlib.sha1(_BLOB).digest()).decode()  # noqa: S324
OTHER_SHA256_HEX = hashlib.sha256(_OTHER).hexdigest()

#: What Yarn Berry writes in the field a lockfile reader puts into `integrity`.
#: A digest of Yarn's own cache entry, prefixed with the cache key -- never
#: equal to the tarball hash a registry publishes.
YARN_BERRY_CHECKSUM = "10c0/" + hashlib.sha512(_BLOB).hexdigest()


class TestIntegrity(RegistryDetectorFixtures):
    def test_a_contradicted_hash_is_critical(self, answer) -> None:
        answer(PackageFacts(name="example", version="1.0.0", digests=(OTHER_SHA256_HEX,)))
        findings = RegistryDetector().inspect(
            GraphUnit(
                dependencies=(RegistryDetectorHelpers.dependency(integrity=f"sha256:{SHA256_HEX}"),)
            ),
            RegistryDetectorHelpers.context(),
        )
        mismatch = [f for f in findings if f.rule_id == "SUSPECT.PROVENANCE.MISMATCH.001"]
        assert mismatch
        assert mismatch[0].severity is Severity.CRITICAL

    def test_matching_hashes_are_silent(self, answer) -> None:
        answer(PackageFacts(name="example", version="1.0.0", digests=(SHA256_HEX,)))
        assert "SUSPECT.PROVENANCE.MISMATCH.001" not in RegistryDetectorHelpers.ids_for(
            RegistryDetectorHelpers.dependency(integrity=f"sha256:{SHA256_HEX}")
        )

    def test_framing_differences_are_not_conflicts(self, answer) -> None:
        """Lockfiles write `sha512-<b64>`, `sha256:<hex>` or a bare digest. The
        framing differs by tool and says nothing about the artefact."""
        answer(PackageFacts(name="example", version="1.0.0", digests=(SHA512_SRI,)))
        assert "SUSPECT.PROVENANCE.MISMATCH.001" not in RegistryDetectorHelpers.ids_for(
            RegistryDetectorHelpers.dependency(integrity=SHA512_SRI.replace("sha512-", "sha512:"))
        )
        answer(PackageFacts(name="example", version="1.0.0", digests=(SHA256_HEX,)))
        assert "SUSPECT.PROVENANCE.MISMATCH.001" not in RegistryDetectorHelpers.ids_for(
            RegistryDetectorHelpers.dependency(integrity=f"sha256:{SHA256_HEX}")
        )

    def test_a_yarn_berry_checksum_is_not_a_conflict(self, answer) -> None:
        """Yarn Berry's `checksum:` is a hash of its own cache entry, not of the
        published tarball, so it can never equal what npm serves. Comparing the
        two reported every dependency of every Berry lockfile as a CRITICAL
        mismatch on an untouched, correct lockfile."""
        answer(PackageFacts(name="example", version="1.0.0", digests=(SHA512_SRI, SHA1_HEX)))
        assert "SUSPECT.PROVENANCE.MISMATCH.001" not in RegistryDetectorHelpers.ids_for(
            RegistryDetectorHelpers.dependency(integrity=YARN_BERRY_CHECKSUM)
        )

    def test_a_go_module_digest_is_not_a_conflict(self, answer) -> None:
        """`go.sum` records `h1:<base64>`, which names no algorithm this
        compares and is not a registry digest."""
        answer(PackageFacts(name="example", version="1.0.0", digests=(SHA512_SRI,)))
        assert "SUSPECT.PROVENANCE.MISMATCH.001" not in RegistryDetectorHelpers.ids_for(
            RegistryDetectorHelpers.dependency(
                integrity="h1:DqDEcV5aeaTmdFBePNpYsp3FlcVH/2ISVVM9Qf8PSls="
            )
        )

    def test_a_different_algorithm_is_not_a_conflict(self, answer) -> None:
        """npm publishes a sha512 `integrity` beside a sha1 `shasum`. A lockfile
        recording the sha1 contradicts neither: a sha1 that does not appear among
        the sha512s is the ordinary case, not evidence."""
        answer(PackageFacts(name="example", version="1.0.0", digests=(SHA512_SRI, SHA1_HEX)))
        assert "SUSPECT.PROVENANCE.MISMATCH.001" not in RegistryDetectorHelpers.ids_for(
            RegistryDetectorHelpers.dependency(integrity=SHA1_SRI)
        )

    def test_an_absent_hash_is_not_a_conflict(self, answer) -> None:
        """A lockfile with no hash is already reported by the offline integrity
        rule, and a registry publishing none cannot contradict anything.
        Treating either as a mismatch would fire on the ordinary case and mean
        nothing on the real one."""
        answer(PackageFacts(name="example", version="1.0.0", digests=()))
        assert "SUSPECT.PROVENANCE.MISMATCH.001" not in RegistryDetectorHelpers.ids_for(
            RegistryDetectorHelpers.dependency(integrity=f"sha256:{SHA256_HEX}")
        )
        answer(PackageFacts(name="example", version="1.0.0", digests=(SHA256_HEX,)))
        assert "SUSPECT.PROVENANCE.MISMATCH.001" not in RegistryDetectorHelpers.ids_for(
            RegistryDetectorHelpers.dependency(integrity=None)
        )


class TestDistance(RegistryDetectorFixtures):
    def test_a_far_behind_pin_is_noted(self, answer) -> None:
        answer(PackageFacts(name="example", version="1.0.0", latest="4.2.0"))
        assert "POLICY.DEPENDENCY.DOWNGRADE.001" in RegistryDetectorHelpers.ids_for(
            RegistryDetectorHelpers.dependency()
        )

    def test_one_major_behind_is_ordinary(self, answer) -> None:
        answer(PackageFacts(name="example", version="1.0.0", latest="2.0.0"))
        assert "POLICY.DEPENDENCY.DOWNGRADE.001" not in RegistryDetectorHelpers.ids_for(
            RegistryDetectorHelpers.dependency()
        )

    def test_an_unparseable_version_does_not_guess(self, answer) -> None:
        answer(PackageFacts(name="example", version="2024-final", latest="4.0.0"))
        assert "POLICY.DEPENDENCY.DOWNGRADE.001" not in RegistryDetectorHelpers.ids_for(
            RegistryDetectorHelpers.dependency(version="2024-final")
        )


class TestUnansweredQuestions(RegistryDetectorFixtures):
    def test_an_unreachable_registry_is_reported(self, answer) -> None:
        """ "We could not ask" and "the answer was no" are different facts, and
        only one of them means there is nothing to worry about."""
        answer(RegistryError("URLError asking pypi.org"))
        found = RegistryDetectorHelpers.ids_for(RegistryDetectorHelpers.dependency())
        assert found == ["OPERATIONAL.REGISTRY.UNREACHABLE.001"]

    def test_that_report_cannot_be_hidden_by_a_threshold(self, answer) -> None:
        answer(RegistryError("URLError asking pypi.org"))
        findings = list(
            RegistryDetector().inspect(
                GraphUnit(dependencies=(RegistryDetectorHelpers.dependency(),)),
                RegistryDetectorHelpers.context(),
            )
        )
        assert findings[0].always_report is True
        assert findings[0].category is Category.OPERATIONAL

    def test_failures_are_aggregated(self, answer) -> None:
        """One finding, not one per package: an offline runner would otherwise
        produce a finding for every dependency in the graph."""
        answer(RegistryError("URLError asking pypi.org"))
        deps = tuple(RegistryDetectorHelpers.dependency(f"pkg{i}") for i in range(20))
        findings = list(
            RegistryDetector().inspect(
                GraphUnit(dependencies=deps), RegistryDetectorHelpers.context()
            )
        )
        assert len(findings) == 1
        assert "20 package(s)" in findings[0].message


class TestTheNetworkCaveat(RegistryDetectorFixtures):
    def test_every_finding_says_where_its_answer_came_from(self, answer) -> None:
        """Rerun offline and it disappears; rerun next week and it may differ.
        A report that did not say so would claim a reproducibility it does not
        have."""
        answer(PackageFacts(name="example", version="1.0.0", yanked=True))
        findings = list(
            RegistryDetector().inspect(
                GraphUnit(dependencies=(RegistryDetectorHelpers.dependency(),)),
                RegistryDetectorHelpers.context(),
            )
        )
        assert findings
        for finding in findings:
            assert any("registry query" in note for note in finding.explanation.escalations)


class TestTheSourceAPackageClaims(RegistryDetectorFixtures):
    """A manifest names the repository a package is built from. The registry
    records one too, and nothing enforces that they agree -- which matters
    because the link in the manifest is the one people actually follow."""

    @staticmethod
    def manifest_unit(repository: str, *, name: str = "example") -> FileUnit:
        import json

        document = json.dumps({"name": name, "version": "1.0.0", "repository": repository})
        return FileUnit(
            content=FileContent.from_bytes("package.json", document.encode("utf-8")),
            language="json",
        )

    def findings_for(self, unit: FileUnit, ctx: ScanContext | None = None) -> list[str]:
        return [
            f.rule_id
            for f in RegistryDetector().inspect(unit, ctx or RegistryDetectorHelpers.context())
        ]

    def test_a_different_repository_is_reported(self, answer) -> None:
        answer(
            PackageFacts(
                name="example", version="1.0.0", repository="https://github.com/attacker/example"
            )
        )
        unit = self.manifest_unit("https://github.com/honest/example")
        assert "SUSPECT.PACKAGE.REPOSITORY.001" in self.findings_for(unit)

    @pytest.mark.parametrize(
        "declared",
        [
            "git@github.com:honest/example.git",
            "git+https://github.com/honest/example.git",
            "github:honest/example",
            "honest/example",
            "https://www.github.com/Honest/Example/",
            "https://github.com/honest/example/tree/main/packages/core",
        ],
    )
    def test_the_same_repository_written_differently_is_not(self, answer, declared: str) -> None:
        """Every one of these is the same repository. A comparison that read
        them as different would fire on most packages that use anything but
        the plain HTTPS spelling, which is most packages."""
        answer(
            PackageFacts(
                name="example", version="1.0.0", repository="https://github.com/honest/example"
            )
        )
        assert self.findings_for(self.manifest_unit(declared)) == []

    def test_a_package_the_registry_does_not_know_is_not(self, answer) -> None:
        """The ordinary case for anything unpublished, which is most manifests
        in most repositories."""
        answer(RegistryError("404 asking registry.npmjs.org"))
        assert self.findings_for(self.manifest_unit("https://github.com/honest/example")) == []

    def test_a_registry_recording_no_repository_is_not(self, answer) -> None:
        answer(PackageFacts(name="example", version="1.0.0", repository=None))
        assert self.findings_for(self.manifest_unit("https://github.com/honest/example")) == []

    def test_a_manifest_declaring_no_repository_is_not(self, answer) -> None:
        import json

        answer(
            PackageFacts(
                name="example", version="1.0.0", repository="https://github.com/other/example"
            )
        )
        unit = FileUnit(
            content=FileContent.from_bytes(
                "package.json", json.dumps({"name": "example", "version": "1.0.0"}).encode()
            ),
            language="json",
        )
        assert self.findings_for(unit) == []

    def test_it_does_not_ask_offline(self, answer) -> None:
        answer(
            PackageFacts(
                name="example", version="1.0.0", repository="https://github.com/attacker/example"
            )
        )
        unit = self.manifest_unit("https://github.com/honest/example")
        assert self.findings_for(unit, RegistryDetectorHelpers.context(offline=True)) == []

    def test_the_finding_points_at_the_manifest(self, answer) -> None:
        answer(
            PackageFacts(
                name="example", version="1.0.0", repository="https://github.com/attacker/example"
            )
        )
        unit = self.manifest_unit("https://github.com/honest/example")
        found = list(RegistryDetector().inspect(unit, RegistryDetectorHelpers.context()))
        assert [f.location.path for f in found] == ["package.json"]


class TestReducingARepositoryToItsIdentity(RegistryDetectorFixtures):
    @pytest.mark.parametrize(
        ("url", "identity"),
        [
            ("https://github.com/o/r", ("github.com", "o", "r")),
            ("git@github.com:o/r.git", ("github.com", "o", "r")),
            ("git+ssh://git@gitlab.com/o/r.git", ("gitlab.com", "o", "r")),
            ("bitbucket:o/r", ("bitbucket.org", "o", "r")),
            ("https://user:token@github.com/o/r", ("github.com", "o", "r")),
        ],
    )
    def test_a_spelling_reduces_to_the_repository_it_names(self, url, identity) -> None:
        assert RegistryEvidence.repository_identity(url) == identity

    @pytest.mark.parametrize("url", [None, "", "   ", "https://example.com", "not a url", "o"])
    def test_something_that_names_no_repository_reduces_to_nothing(self, url) -> None:
        """Returned rather than guessed at. A claim that cannot be resolved is
        one the caller must stay quiet about, not one it may compare."""
        assert RegistryEvidence.repository_identity(url) is None


class TestProvenanceThatWasThereForEveryOtherRelease(RegistryDetectorFixtures):
    """A package that has never published provenance says nothing by not
    publishing it. A package that published it thirty times and not for the
    version pinned here is a release that did not come from the pipeline the
    others came from, which is what a stolen publishing token produces."""

    def test_a_gap_in_an_attested_package_is_reported(self, answer) -> None:
        answer(
            PackageFacts(
                name="example",
                version="1.0.0",
                attested=False,
                attested_versions=30,
                latest="1.0.0",
            )
        )
        assert "SUSPECT.PACKAGE.PROVENANCE.001" in RegistryDetectorHelpers.ids_for(
            RegistryDetectorHelpers.dependency()
        )

    def test_an_attested_version_is_not(self, answer) -> None:
        answer(
            PackageFacts(
                name="example", version="1.0.0", attested=True, attested_versions=30, latest="1.0.0"
            )
        )
        assert RegistryDetectorHelpers.ids_for(RegistryDetectorHelpers.dependency()) == []

    def test_a_package_that_never_attests_is_not(self, answer) -> None:
        """The majority of packages. Reporting them would be reporting the
        state of the ecosystem, one finding per dependency."""
        answer(
            PackageFacts(
                name="example", version="1.0.0", attested=False, attested_versions=0, latest="1.0.0"
            )
        )
        assert RegistryDetectorHelpers.ids_for(RegistryDetectorHelpers.dependency()) == []

    def test_a_package_that_has_just_started_is_not(self, answer) -> None:
        """One or two attested releases is a project trying it out, and every
        older pin would otherwise be reported the week they did."""
        answer(
            PackageFacts(
                name="example", version="1.0.0", attested=False, attested_versions=2, latest="1.0.0"
            )
        )
        assert RegistryDetectorHelpers.ids_for(RegistryDetectorHelpers.dependency()) == []


class TestReadingAttestationFromARegistryResponse(RegistryDetectorFixtures):
    ORDERED: ClassVar[dict[str, Any]] = {
        "dist-tags": {"latest": "3.0.0"},
        "time": {
            "1.0.0": "2024-01-01T00:00:00Z",
            "2.0.0": "2024-06-01T00:00:00Z",
            "3.0.0": "2024-09-01T00:00:00Z",
        },
        "versions": {
            "1.0.0": {"dist": {"integrity": "sha512-a", "attestations": {"url": "https://x"}}},
            "2.0.0": {"dist": {"integrity": "sha512-b", "attestations": {"url": "https://y"}}},
            "3.0.0": {"dist": {"integrity": "sha512-c"}},
        },
    }

    def test_npm_records_the_bundle_against_the_version(self) -> None:
        observed = RegistryDetectorHelpers._npm_from(self.ORDERED, "example", "3.0.0")
        assert observed.attested is False
        assert observed.attested_versions == 2

    def test_only_the_siblings_that_came_first_are_counted(self) -> None:
        """A package that started attesting last month would otherwise make
        every older pin look like a gap. `requests==2.31.0` predates the
        practice; it did not skip anything."""
        observed = RegistryDetectorHelpers._npm_from(self.ORDERED, "example", "1.0.0")
        assert observed.attested is True
        assert observed.attested_versions == 0

    def test_a_packument_with_no_times_counts_nothing(self) -> None:
        """Without the ordering there is no question to answer, and guessing
        would put the finding on exactly the pins that predate attestation."""
        document = {k: v for k, v in self.ORDERED.items() if k != "time"}
        assert (
            RegistryDetectorHelpers._npm_from(document, "example", "3.0.0").attested_versions == 0
        )

    def test_a_malformed_dist_is_read_as_unattested(self) -> None:
        """Registry metadata is written by whoever published the package. A
        field documented as an object arrives as whatever they put there, and
        the answer to that must be "no attestation", not an exception halfway
        through a scan."""
        document = {"versions": {"1.0.0": {"dist": {"attestations": "yes, definitely"}}}}
        observed = RegistryDetectorHelpers._npm_from(document, "example", "1.0.0")
        assert observed.attested is False
        assert observed.attested_versions == 0


class TestTheRegistryIsNotAskedUnboundedly(RegistryDetectorFixtures):
    def test_a_monorepo_does_not_produce_a_request_per_manifest(self, answer) -> None:
        """Hundreds of sequential requests is slow enough that people stop
        passing `--online`, which is worse than a ceiling."""
        import json

        from cordon_scanner.detect.registry import MAX_MANIFEST_QUERIES

        answer(
            PackageFacts(
                name="example", version="1.0.0", repository="https://github.com/attacker/example"
            )
        )
        detector = RegistryDetector()
        ctx = RegistryDetectorHelpers.context()
        found = 0
        for index in range(MAX_MANIFEST_QUERIES + 20):
            document = json.dumps(
                {
                    "name": f"example-{index}",
                    "version": "1.0.0",
                    "repository": "https://github.com/honest/example",
                }
            )
            unit = FileUnit(
                content=FileContent.from_bytes(
                    f"packages/p{index}/package.json", document.encode("utf-8")
                ),
                language="json",
            )
            found += len(list(detector.inspect(unit, ctx)))
        assert found == MAX_MANIFEST_QUERIES


class TestDeprecationAndMaintenance(RegistryDetectorFixtures):
    """Socket's deprecated and unmaintained alerts: the publisher's notice, and the last release."""

    def test_a_deprecated_version_is_reported_with_its_notice(self, answer) -> None:
        answer(PackageFacts(name="example", version="1.0.0", deprecated="Use example2 instead"))
        dep = RegistryDetectorHelpers.dependency()
        [finding] = list(
            RegistryDetector().inspect(
                GraphUnit(dependencies=(dep,)), RegistryDetectorHelpers.context()
            )
        )
        assert finding.rule_id == "POLICY.DEPENDENCY.DEPRECATED.001"
        assert "Use example2 instead" in finding.message

    @pytest.mark.parametrize(
        "notice",
        [
            "Critical security vulnerability fixed in 1.0.1",
            "This version was compromised, upgrade now",
            "contains malicious code",
            "see CVE-2024-12345",
        ],
    )
    def test_a_deprecation_citing_security_is_suspect(self, answer, notice: str) -> None:
        answer(PackageFacts(name="example", version="1.0.0", deprecated=notice))
        assert RegistryDetectorHelpers.ids_for(RegistryDetectorHelpers.dependency()) == [
            "SUSPECT.DEPENDENCY.DEPRECATED_SECURITY.001"
        ]

    def test_publisher_text_is_neutralised_before_it_is_quoted(self, answer) -> None:
        hostile = "ok\x1b[2J\u202eevil\u200b " + "x" * 500
        answer(PackageFacts(name="example", version="1.0.0", deprecated=hostile))
        dep = RegistryDetectorHelpers.dependency()
        [finding] = list(
            RegistryDetector().inspect(
                GraphUnit(dependencies=(dep,)), RegistryDetectorHelpers.context()
            )
        )
        assert (
            "\x1b" not in finding.message
            and "\u202e" not in finding.message
            and "\u200b" not in finding.message
        )
        assert len(finding.message) < 400

    def test_a_package_silent_for_five_years_is_noted(self, answer) -> None:
        answer(PackageFacts(name="example", version="1.0.0", last_published="2015-03-01T00:00:00Z"))
        assert RegistryDetectorHelpers.ids_for(RegistryDetectorHelpers.dependency()) == [
            "POLICY.DEPENDENCY.UNMAINTAINED.001"
        ]

    @pytest.mark.parametrize("when", [None, "", "not-a-date", "2999-01-01T00:00:00Z"])
    def test_a_recent_or_unknown_release_date_is_silent(self, answer, when) -> None:
        import datetime

        recent = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=30)).isoformat()
        answer(PackageFacts(name="example", version="1.0.0", last_published=when))
        assert RegistryDetectorHelpers.ids_for(RegistryDetectorHelpers.dependency()) == []
        answer(PackageFacts(name="example", version="1.0.0", last_published=recent))
        assert RegistryDetectorHelpers.ids_for(RegistryDetectorHelpers.dependency()) == []

    def test_deprecation_takes_the_place_of_the_maintenance_note(self, answer) -> None:
        answer(
            PackageFacts(
                name="example",
                version="1.0.0",
                deprecated="gone",
                last_published="2010-01-01T00:00:00Z",
            )
        )
        assert RegistryDetectorHelpers.ids_for(RegistryDetectorHelpers.dependency()) == [
            "POLICY.DEPENDENCY.DEPRECATED.001"
        ]

    def test_the_npm_reader_takes_the_notice_and_the_latest_release(self) -> None:
        document = {
            "versions": {"1.0.0": {"deprecated": "  use v2  "}, "2.0.0": {}},
            "time": {
                "created": "2015-01-01T00:00:00Z",
                "modified": "2026-01-01T00:00:00Z",
                "1.0.0": "2015-01-01T00:00:00Z",
                "2.0.0": "2019-06-01T00:00:00Z",
            },
            "dist-tags": {"latest": "2.0.0"},
        }
        facts = RegistryDetectorHelpers._npm_from(document, "example", "1.0.0")
        assert facts.deprecated == "use v2"
        # `modified` moves on every metadata edit; only a release counts.
        assert facts.last_published == "2019-06-01T00:00:00Z"
        assert RegistryDetectorHelpers._npm_from(document, "example", "2.0.0").deprecated is None

    def test_the_pypi_reader_takes_the_inactive_classifier(self) -> None:
        import unittest.mock

        from cordon_scanner.intel import registry_client

        document = {
            "info": {"version": "1.0.0", "classifiers": ["Development Status :: 7 - Inactive"]},
            "releases": {"1.0.0": [{"upload_time_iso_8601": "2016-01-01T00:00:00Z"}]},
        }
        with (
            unittest.mock.patch.object(
                registry_client.RegistryClient, "_fetch", return_value=document
            ),
            unittest.mock.patch.object(
                registry_client.RegistryClient, "_pypi_attestations", return_value=(False, 0)
            ),
        ):
            facts = registry_client.RegistryClient._pypi("example", "1.0.0")
        assert facts.deprecated and "Inactive" in facts.deprecated
        assert facts.last_published == "2016-01-01T00:00:00Z"


class TestStarjacking(RegistryDetectorFixtures):
    """A young package borrowing a popular project's repository, and the monorepos that are not."""

    @staticmethod
    def recent() -> str:
        import datetime

        return (datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=10)).isoformat()

    def test_a_new_package_naming_a_popular_projects_repository_is_reported(self, answer) -> None:
        answer(
            PackageFacts(
                name="reqests-helper",
                version="1.0.0",
                repository="https://github.com/psf/requests",
                first_published=self.recent(),
            )
        )
        dep = RegistryDetectorHelpers.dependency("reqests-helper")
        [finding] = list(
            RegistryDetector().inspect(
                GraphUnit(dependencies=(dep,)), RegistryDetectorHelpers.context()
            )
        )
        assert finding.rule_id == "SUSPECT.PACKAGE.STARJACKING.001"
        assert "github.com/psf/requests" in finding.message

    @pytest.mark.parametrize(
        ("name", "ecosystem", "repository"),
        [
            ("requests", "pypi", "https://github.com/psf/requests"),
            ("requests-mock-extra", "pypi", "https://github.com/psf/requests"),
            ("@babel/plugin-new", "npm", "https://github.com/babel/babel"),
            ("@react/thing", "npm", "https://github.com/react/react"),
            ("my-tool", "pypi", "https://github.com/me/my-tool"),
            ("other", "pypi", "https://github.com/me/not-a-popular-name-xyz"),
        ],
    )
    def test_the_packages_own_repository_and_monorepos_are_not(
        self, answer, name, ecosystem, repository
    ) -> None:
        answer(
            PackageFacts(
                name=name, version="1.0.0", repository=repository, first_published=self.recent()
            )
        )
        dep = RegistryDetectorHelpers.dependency(name, ecosystem=ecosystem)
        assert "SUSPECT.PACKAGE.STARJACKING.001" not in RegistryDetectorHelpers.ids_for(dep)

    def test_an_established_package_is_not(self, answer) -> None:
        answer(
            PackageFacts(
                name="reqests-helper",
                version="1.0.0",
                repository="https://github.com/psf/requests",
                first_published="2015-01-01T00:00:00Z",
            )
        )
        assert (
            RegistryDetectorHelpers.ids_for(RegistryDetectorHelpers.dependency("reqests-helper"))
            == []
        )
