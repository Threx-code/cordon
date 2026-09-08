"""M-06: the advisory layer, which did not exist.

`Category.VULNERABLE` was defined, documented ("A known weakness in something
depended upon. CVE, GHSA, OSV"), threaded through severity floors, policy,
filtering and every reporter -- and emitted by nothing. `Confidence.CONFIRMED`
was documented as reserved for "an exact package-and-version match against the
threat-intelligence database", and no such database existed, so the highest
confidence the model defines was unreachable.
"""

from __future__ import annotations

import json
import re

import pytest

from cordon import Scanner
from cordon.core.config import Config
from cordon.core.errors import ConfigError
from cordon.core.models import Category, Confidence
from cordon.core.registry import Registry
from cordon.detect.advisory import AdvisoryDetector
from cordon.intel.advisories import BUNDLED, Advisory, AdvisoryDatabase


def lockfile(entries) -> str:
    packages = {"": {"name": "app"}}
    for path, name, version in entries:
        packages[path] = {
            "version": version,
            "integrity": "sha512-x",
            "resolved": f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz",
        }
    return json.dumps({"lockfileVersion": 3, "packages": packages})


@pytest.fixture
def project(tmp_path):
    (tmp_path / "package.json").write_text('{"name":"app","version":"1.0.0"}')
    return tmp_path


def scan(root, detectors=None):
    cfg = Config.default().with_overrides(use_cache=False)
    return Scanner(cfg, detectors=detectors).scan(root)


class TestBundledDatabase:
    def test_it_is_not_empty(self) -> None:
        assert len(AdvisoryDatabase.bundled()) >= 5

    def test_every_record_names_a_reference(self) -> None:
        """So a reader can check it rather than trust it."""
        from cordon.intel.advisories import BUNDLED

        for advisory in BUNDLED:
            assert advisory.reference.startswith("http"), advisory.name
            assert advisory.summary

    def test_it_matches_an_affected_version(self) -> None:
        db = AdvisoryDatabase.bundled()
        assert db.matching("npm", "event-stream", "3.3.6")

    def test_it_does_not_match_a_neighbouring_version(self) -> None:
        """The name is shared with every version that was never compromised."""
        db = AdvisoryDatabase.bundled()
        assert not db.matching("npm", "event-stream", "3.3.5")

    def test_a_dependency_with_no_version_never_matches(self) -> None:
        """Matching one would mean flagging a package by name alone."""
        db = AdvisoryDatabase.bundled()
        assert not db.matching("npm", "event-stream", None)

    def test_the_ecosystem_is_part_of_the_key(self) -> None:
        db = AdvisoryDatabase.bundled()
        assert not db.matching("pypi", "event-stream", "3.3.6")


class TestKnownMaliciousDependency:
    def test_it_is_reported(self, project) -> None:
        (project / "package-lock.json").write_text(
            lockfile([("node_modules/event-stream", "event-stream", "3.3.6")])
        )
        assert "MALWARE.DEPENDENCY.KNOWN.001" in {f.rule_id for f in scan(project).findings}

    def test_it_is_the_one_place_confirmed_is_used(self, project) -> None:
        """An identity match against a recorded incident is the only thing that
        earns it: no inference, no heuristic, no pattern that might mean
        something else."""
        (project / "package-lock.json").write_text(
            lockfile([("node_modules/ua-parser-js", "ua-parser-js", "0.7.29")])
        )
        finding = next(
            f for f in scan(project).findings if f.rule_id == "MALWARE.DEPENDENCY.KNOWN.001"
        )
        assert finding.confidence is Confidence.CONFIRMED
        assert finding.category is Category.MALICIOUS

    def test_it_fails_the_build(self, project) -> None:
        from cordon.core.errors import ExitCode
        from cordon.core.policy import PolicyGate

        (project / "package-lock.json").write_text(
            lockfile([("node_modules/event-stream", "event-stream", "3.3.6")])
        )
        cfg = Config.default().with_overrides(use_cache=False)
        verdict = PolicyGate.evaluate(Scanner(cfg).scan(project), cfg.policy)
        assert verdict.exit_code is ExitCode.FINDINGS

    def test_an_unaffected_version_is_not_reported(self, project) -> None:
        (project / "package-lock.json").write_text(
            lockfile([("node_modules/event-stream", "event-stream", "3.3.5")])
        )
        assert "MALWARE.DEPENDENCY.KNOWN.001" not in {f.rule_id for f in scan(project).findings}

    def test_an_ordinary_dependency_is_not_reported(self, project) -> None:
        (project / "package-lock.json").write_text(
            lockfile([("node_modules/express", "express", "4.18.2")])
        )
        assert not [f for f in scan(project).findings if "KNOWN" in f.rule_id]

    def test_the_finding_anchors_to_the_lockfile(self, project) -> None:
        (project / "package-lock.json").write_text(
            lockfile([("node_modules/event-stream", "event-stream", "3.3.6")])
        )
        finding = next(
            f for f in scan(project).findings if f.rule_id == "MALWARE.DEPENDENCY.KNOWN.001"
        )
        assert finding.location.path == "package-lock.json"
        assert finding.references


class TestVulnerableCategory:
    """Reachable at last. Previously no code path emitted it."""

    def custom(self, tmp_path, records):
        path = tmp_path / "advisories.json"
        path.write_text(json.dumps(records))
        database = AdvisoryDatabase.from_file(path)
        others = [d for d in Registry().detectors() if d.id != "advisory"]
        return [*others, AdvisoryDetector(database)]

    def test_a_vulnerable_dependency_is_reported(self, project, tmp_path) -> None:
        (project / "package-lock.json").write_text(
            lockfile([("node_modules/express", "express", "4.18.2")])
        )
        detectors = self.custom(
            tmp_path,
            [
                {
                    "ecosystem": "npm",
                    "name": "express",
                    "versions": ["4.18.2"],
                    "malicious": False,
                    "summary": "A worked example, not a real advisory.",
                    "reference": "https://example.invalid",
                    "id": "TEST-0001",
                }
            ],
        )
        findings = [
            f for f in scan(project, detectors).findings if f.category is Category.VULNERABLE
        ]
        assert findings
        assert findings[0].confidence is Confidence.CONFIRMED

    def test_a_supplied_database_replaces_the_bundled_one(self, project, tmp_path) -> None:
        """An organisation supplying its own is stating what it considers
        authoritative; merging a shipped list in would produce findings it did
        not choose to act on."""
        (project / "package-lock.json").write_text(
            lockfile([("node_modules/event-stream", "event-stream", "3.3.6")])
        )
        detectors = self.custom(tmp_path, [])
        assert not [f for f in scan(project, detectors).findings if "KNOWN" in f.rule_id]


class TestLoadingAnExport:
    def test_a_malformed_file_is_a_config_error(self, tmp_path) -> None:
        path = tmp_path / "bad.json"
        path.write_text("not json")
        with pytest.raises(ConfigError):
            AdvisoryDatabase.from_file(path)

    def test_a_non_list_document_is_refused(self, tmp_path) -> None:
        path = tmp_path / "bad.json"
        path.write_text('{"ecosystem": "npm"}')
        with pytest.raises(ConfigError, match="list"):
            AdvisoryDatabase.from_file(path)

    def test_a_missing_field_names_the_entry(self, tmp_path) -> None:
        path = tmp_path / "bad.json"
        path.write_text('[{"ecosystem": "npm", "name": "x"}]')
        with pytest.raises(ConfigError, match="entry 0"):
            AdvisoryDatabase.from_file(path)

    def test_a_well_formed_export_loads(self, tmp_path) -> None:
        path = tmp_path / "ok.json"
        path.write_text(
            json.dumps(
                [
                    {
                        "ecosystem": "pypi",
                        "name": "example",
                        "versions": ["1.0.0"],
                        "malicious": True,
                        "summary": "s",
                        "reference": "https://example.invalid",
                        "id": "X-1",
                    }
                ]
            )
        )
        database = AdvisoryDatabase.from_file(path)
        assert len(database) == 1
        assert database.matching("pypi", "example", "1.0.0")


class TestBundledIdentifiers:
    """Whether the bundled advisory records say true things.

    Every field here is a claim a reader can check, and the identifier is the
    one they will actually follow. Four of the nine records shipped with a wrong
    one: an identifier belonging to an unrelated advisory, two separate
    incidents folded into a single record, and one identifier that did not
    exist. All four had the right shape, which is exactly why review did not
    catch them.

    The offline tests below catch the shape errors. They cannot catch a
    well-formed identifier for the wrong advisory, so `TestAgainstOsv` does that
    against the live database and is deselected by default -- a test suite that
    fails when the network is down teaches people to ignore it.
    """

    IDENTIFIER = re.compile(
        r"^(?:GHSA-[2-9a-hjkmnp-z]{4}-[2-9a-hjkmnp-z]{4}-[2-9a-hjkmnp-z]{4}|(?:PYSEC|MAL)-\d{4}-\d+|CVE-\d{4}-\d{4,})$"
    )

    def test_every_identifier_is_well_formed_or_absent(self) -> None:
        for advisory in BUNDLED:
            if not advisory.identifier:
                continue
            assert self.IDENTIFIER.match(advisory.identifier), advisory.identifier

    def test_no_identifier_is_a_placeholder(self) -> None:
        """`GHSA-vqrf-vqrf-vqrf` passed every structural check and pointed at
        nothing. A repeated segment is the signature of an invented one."""
        for advisory in BUNDLED:
            segments = advisory.identifier.split("-")[1:]
            assert len(set(segments)) == len(segments), advisory.identifier

    def test_every_record_names_a_reference(self) -> None:
        for advisory in BUNDLED:
            assert advisory.reference.startswith("https://"), advisory.name

    def test_a_record_with_an_identifier_references_it(self) -> None:
        """So the link a reader follows is the advisory the record claims,
        rather than a blog post about the same incident."""
        for advisory in BUNDLED:
            if advisory.identifier:
                assert advisory.identifier in advisory.reference, advisory.name

    def test_one_record_per_advisory(self) -> None:
        """Two incidents in one record makes the identifier wrong for whichever
        version matched. node-ipc shipped that way."""
        identifiers = [a.identifier for a in BUNDLED if a.identifier]
        assert len(set(identifiers)) == len(identifiers)

    def test_no_version_is_claimed_by_two_records_for_one_package(self) -> None:
        seen: set[tuple[str, str, str]] = set()
        for advisory in BUNDLED:
            for version in advisory.versions:
                key = (advisory.ecosystem, advisory.name.lower(), version)
                assert key not in seen, key
                seen.add(key)

    def test_every_record_lists_versions(self) -> None:
        """A record with no versions matches nothing, so it is a claim the tool
        can never act on."""
        for advisory in BUNDLED:
            assert advisory.versions, advisory.name


@pytest.mark.network
class TestAgainstOsv:
    """The check the offline tests cannot make.

    Deselected by default. Run with `pytest -m network` before a release, which
    is when a bundled advisory being wrong actually costs something.
    """

    def osv(self, identifier: str) -> dict[str, object] | None:
        import json
        import urllib.error
        import urllib.request

        try:
            with urllib.request.urlopen(
                f"https://api.osv.dev/v1/vulns/{identifier}", timeout=30
            ) as response:
                loaded: dict[str, object] = json.load(response)
                return loaded
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise

    @pytest.mark.parametrize(
        "advisory", [a for a in BUNDLED if a.identifier], ids=lambda a: a.identifier
    )
    def test_the_identifier_exists(self, advisory: Advisory) -> None:
        assert self.osv(advisory.identifier) is not None

    @pytest.mark.parametrize(
        "advisory", [a for a in BUNDLED if a.identifier], ids=lambda a: a.identifier
    )
    def test_the_identifier_names_this_package(self, advisory: Advisory) -> None:
        """The failure that shape checks miss: a real identifier for a real
        advisory about something else entirely."""
        record = self.osv(advisory.identifier)
        assert record is not None
        affected = record.get("affected") or []
        names = {
            str(entry.get("package", {}).get("name", "")).lower()
            for entry in affected
            if isinstance(entry, dict)
        }
        assert advisory.name.lower() in names, sorted(names)
